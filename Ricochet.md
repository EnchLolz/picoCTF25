# Ricochet - Writeup

## **Description**

I bought this robot to help me locate flags, but the controller is stuck in a demo loop where the robot just goes in circles. Can you exploit the encryption between the controller to navigate the robot to the flag?

Additional details will be available after launching your challenge instance.

## Artifacts Provided

- crypto.py - Cryptographic protocol implementation
- radio_interface.py - Functions for us to read and write messages into the communication stream for the robot
- robot.py - Robot movement code
- robotcontroller.py - Robot contoller code

## Initial Thoughts

So I immediately realized that it wouldn’t be viable to break the encryption protocol used by the controller and the robot, since it generates a challenge that would be infeasible to guess before verification. I also realized that essentially we would act as a MITM with the controller, since we can change the controller’s address and essentially act as them.

I then saw that the nonce was only reset whenever the robot restarted, and the robot’s position would be reset to the top left whenever this happened. So immediately I thought it would be a session replay, where we’d record packets with specific nonces and re-use them later.

Diagram:
![diagram](/images/ricochetdiagram.png)
We mostly only care about the `secure_data_X` stuff.

## Approach A (Incorrect)

So I noticed that whenever `get_movement` was sent, the instruction on the controller would advance by 1. From that, I realized we would probably need to store empty `secure_data_request` and `secure_data_response` messages, and we could do that. If we simply don’t send the `get_movement` initially, the sendbuffer on the controller’s side would remain empty. From there, we could send a bogus `secure_data_ack` to the robot so that the nonces would remain synced, and the while loop in the robot’s side would mean that we get valid empty `secure_data_request` and `secure_data_response` packets.

My next idea was that we should record `get_movement` for nonces 0, 2, 4, 6 … 40 by letting the robot run normally, then record `get_movement` for nonces 1, 3, 5 … 39. I tried to do this by sending an empty `secure_data_response` packet to offset the nonce by 1, but realized this wouldn’t work because the robot would discard any messages that it wasn’t waiting for (e.g. if it sent `secure_data` it would wait for `secure_data_ack` and discard any other message types). I tried other timings, but couldn’t find a way to increment the robot nonce by 1 while maintaining the conversation, since one way or the other the nonces would be desynced and the robot would crash.

I then thought about only using the even nonces, but still ran into the same problem - I couldn’t find a way to increment the nonce on both sides by 1, since we can’t block communication from controller to robot.

## Approach B

I then realized that we don’t actually need to care about the robot crashing - as long as we get one valid message with one valid nonce, we make progress. Therefore, if we could record `secure_data_response` with all four directions for specified nonces, we’d be able to forge communication with the robot and ignore the controller entirely.

I still wanted to record empty `secure_data_request` and `secure_data_response` packets, so I reused my code from part 1. I then recorded `get_movement` for our even nonces and the according `secure_data_request/secure_data_response` pairs (in hindsight, this was probably unnecessary).

I then realized that we could get a single `secure_data_response` with any direction for any valid nonce - but each packet would require restarting the robot. We do this by letting the conversation play normally until before we reach the target direction we want, then send `secure_data` and `secure_data_request`. Since we only have `secure_data` for even nonces, we can only get `secure_data_response` for odd nonces. So, the process now was:

- Play the conversation normally until we reach the direction before the one we want to send (for east, we would stop forwarding messages to the controller immediately after validation).
- Send `secure_data_request` to the controller and empty `secure_data_response` to the client, until we reach the nonce before the one we want.
- Send `get_movement` to the controller and record the response
- Restart the robot and repeat this, but with two more packets sent (record nonce for n + 2)
- Restart the robot and repeat this, with all four directions.

So now that we have `secure_data_response` with directions for everything we could possibly need, we can fake an entire conversation. After validation, we cut off communication between the robot and controller. After receiving `get_movement` we send a bogus `secure_data_ack` packet, and wait until we receive `secure_data_request` . We then account for the nonce offset by adding an empty `secure_data_response` , then send the `secure_data_response` for the direction that we recorded. 

This gives us arbitrary control over the robot’s movement for nonces 0 … 40, which is more than enough to follow our target path and reach the flag.

## Solve Script

```python
import random
import requests
import asyncio
import time
import sys

SERVER_URL = "http://activist-birds.picoctf.net:" + sys.argv[1]

def receive_radio_messages():
    messages = requests.get(SERVER_URL+"/radio_rx").json()
    return messages

def inject_radio_message(message):
    requests.post(SERVER_URL + "/radio_tx", json=message)

def start_robot():
    requests.get(SERVER_URL+"/start")

def stop_robot():
    requests.get(SERVER_URL + "/stop")

def get_board_state():
    return requests.get(SERVER_URL + "/state").json()

def print_pkt(msg):
    copy = msg.copy()
    if 'encrypted' in copy:
        copy['encrypted'] = copy['encrypted'][0:8] + '...'
    print(copy)

# Set robot address so we can MITM

ME = 0x40
CONTROLLER = 0x69
ROBOT = 0x20

inject_radio_message({
    "msg_type": "set_addr",
    "src": ME,
    "dst": 0x10,
    "new_addr": CONTROLLER
})

ME = 0x10

# Bogus ack packet. Used to start recording secure_data_request & secure_data_response
async def bogus_ack():
    ack_packet = {
        'msg_type': 'secure_data_ack',
        'src': ME,
        'dst': ROBOT,
    }
    ack_packet['encrypted'] = '8b58b51c50e420e10f8a34559d13d418bbd2f5c2148c9b66c0f9d4a239971bb1ba3c3cec71fd09ccc650b85a42d15e455c0dee10ff03d83f7472393665ca229ff35335a0a3bfbac119d8260cadf8c77ea833b5c46d9782db25db0a8ba56ce8eb068360343d6c119da7b58157692012fcdf0622854d5266aa13414b8ec4f33d1cbabd84a7a30d9ee7fc8598d966739dcf50387a6b522fc889df505da92db0e2910386af7c18189d;a4fbb351432f4c31dd369c7fee7b31f7;eab0ae99aa6ce479fccfec29e06ee442ffbeb6091753b605'
    inject_radio_message(ack_packet)

# Bogus secure_data_response packet. Used to crash the robot.
async def bogus_response():
    m = {
        'msg_type': 'secure_data_response', 
        'src': ME, 
        'dst': ROBOT, 
    }
    m['encrypted'] = '364a10daa4e52b59cc20b2d14cdac639344a7aba6b5ee924ed4b75f14a68af4b175c455427b067149c285fd672727ff618410e3b586fe81c3ae25ddce5edee93d84cbe339bbe02c26b0a75f5020b9b0af1884389871b5fcbf1b595364a81fc65a08f4ed10486c35f718f73be8fe78d3ebfe11d1071fe6ee70701a1f282f29c8e0efb952c1190003e48054bb6ac3153005121016a3c7e2822e7593beb21819046653dd66dc5672b43;a164b4fa90629ad10ac378e66b435cfa;77c3bfd572f49fc7b967b754c8661c3e6315489e28d8ee33'
    inject_radio_message(m)

# Inject packet with target nonce, to target destination.
async def inject_packet(msg_type, nonce, destination, direction):
    
    candidates = []
    if msg_type == 'secure_data_request':
        candidates = secure_requests
    elif msg_type == 'secure_data_response':
        candidates = secure_responses
    elif 'secure_data' in msg_type:
        candidates = secure_data
    else:
        print("[FATAL ERROR] Unknown/untracked message type! msg_type = " + msg_type)
        
    for item in candidates:
        # Nonce doesn't match what we want
        if nonce != item[1]:
            continue
            
        # Target direction (east, south, west, north) is wrong
        if direction is not None and item[2] != direction:
            continue
            
        item[0]["dst"] = destination
        print('Forging packet... (n=' + str(nonce) + ')', end=' ')
        print_pkt(item[0])
        inject_radio_message(item[0])
        
        return item

    print("[FATAL ERROR] No message found with target nonce & direction! nonce = " + str(nonce) + ", direction = " + str(destination))
    
directions = ['east', 'south', 'west', 'north']
movement_counter = 0

part = 0
nonce = 0

secure_requests = []
secure_responses = []

print('-' * 20 + 'Begin part 1')
### PART 1 -> RECORD EMPTY SECURE_DATA_REQUEST AND SECURE_DATA_RESPONSE PAIRS

async def record_request_response(msg):
    secure_responses_l = 60
    
    global ME 
    global CONTROLLER
    global ROBOT
    
    global part
    global nonce
    
    global secure_requests 
    global secure_responses 
    
    await asyncio.sleep(0.02)

    if msg["dst"] == ME:
        if msg["msg_type"] == "secure_data":
            print("Received SDATA / Injecting bogus SDACK")
            await asyncio.sleep(1)

            await bogus_ack()

            return
        elif msg["msg_type"] == "secure_data_request":
            print("Received SDREQ")
            secure_requests.append((msg, nonce, None))
            
            if len(secure_responses) == secure_responses_l:
                print("Reached enough responses!")
                print("Injecting bogus SDRES")
                await bogus_response()
                
                part = 1
                
                return

            msg["dst"] = CONTROLLER
            inject_radio_message(msg)
            return
        else:
            msg["dst"] = CONTROLLER
            inject_radio_message(msg)
            return

    elif msg["dst"] == ROBOT:
        if msg["msg_type"] == "secure_data_response":
            print("Received SDRES")
            secure_responses.append((msg, nonce, None))
            nonce += 1

time.sleep(1)
start_robot()

while True:
    messages = receive_radio_messages()
    for msg in messages:
        asyncio.run(record_request_response(msg))
        
        if part == 1:
            break 
    
    if part == 1:
        break 

stop_robot()

### PART 1 -> RECORD EMPTY SECURE_DATA_REQUEST AND SECURE_DATA_RESPONSE PAIRS
nonce = 0
receive_radio_messages()
print('-' * 20 + 'Begin part 2')
### PART 2 -> RECORD SECURE_DATA FOR NONCE 0, 2, 4, ... 40 AND SECURE_DATA_RESPONSE FOR NONCES 1, 3, 5, 7, ..., 41

secure_data = []

async def record_secure_data(msg):
    global ME 
    global CONTROLLER
    global ROBOT
    
    global part
    global nonce
    global directions
    global movement_counter 
    
    global secure_requests 
    global secure_responses 
    
    await asyncio.sleep(0.02)

    if msg["dst"] == ME:
        if msg["msg_type"] == "secure_data":
            print("Received SDATA")
            secure_data.append((msg, nonce, None))
            nonce += 1

        msg["dst"] = CONTROLLER
        inject_radio_message(msg)
        return

    elif msg["dst"] == ROBOT:
        if msg["msg_type"] == "secure_data_response":
            print("Received SDRES")
            secure_responses.append((msg, nonce, directions[movement_counter % 4]))
            
            movement_counter += 1
            nonce += 1

    if movement_counter == 20:
        print("Reached 20 movements")
        part = 2
    
time.sleep(2)
start_robot()

while True:
    messages = receive_radio_messages()
    for msg in messages:
        asyncio.run(record_secure_data(msg))
        
        if part == 2:
            break 
    
    if part == 2:
        break 

### PART 2 -> RECORD SECURE_DATA FOR NONCE 0, 2, 4, ... 40 AND SECURE_DATA_RESPONSE FOR NONCES 1, 3, 5, 7, ..., 41
nonce = 0
receive_radio_messages()
print('-' * 20 + 'Begin part 3')
### PART 3 -> SEND SECURE_DATA_REQUEST N - 1 TIMES, THEN SEND SECURE_DATA, THEN SEND SECURE_DATA_REQUEST, THEN RECORD SECURE_DATA_RESPONSE

# Offset the nonce to N and load secure_data_response
async def offset(start, n, direction):
    global CONTROLLER 
    
    if n % 2 != 0:
        print('[FATAL ERROR] Target offset not a multiple of 2')
        return

    for i in range(start, n):
        await inject_packet('secure_data_request', i, CONTROLLER, None)

    expected = n - start + 1 + (start // 2)
    await inject_packet('secure_data', n, CONTROLLER, None)
    await inject_packet('secure_data_response', n, ROBOT, None)
    await inject_packet('secure_data_request', n + 1, CONTROLLER, None)
    
    print ("Waiting for final response...")
    
    while True:
        messages = receive_radio_messages()
        
        for msg in messages:
            print_pkt(msg)
            if msg['msg_type'] == 'secure_data_response':
                expected -= 1
                if expected == 0:
                    print("Received final response!")
                    secure_responses.append((msg, n + 1, direction))
                    return
        
BOUND = 40

# Record responses for [east]
async def record_east():
    global secure_responses
    global BOUND
    
    for n in range(0, BOUND, 2):
        time.sleep(1.5)
        start_robot()
        
        proxying = True
            
        while True:
            messages = receive_radio_messages()
            stop = False
            for msg in messages:  
                if proxying and msg['dst'] == ME:
                    msg['dst'] = CONTROLLER     
                    print_pkt(msg)
                    inject_radio_message(msg)
                elif msg['dst'] == ROBOT:
                    print_pkt(msg)
                    
                # We drop all messages from the robot. This is just used as a anchor point so we know that it has validated properly
                if msg['msg_type'] == 'ack_key_exchange' and msg['dst'] == ROBOT:
                    proxying = False
                    
                    # no original offset
                    
                    # this peforms the rest of the offset
                    await asyncio.sleep(0.02)
                    await offset(0, n, 'east')
                    
                    stop = True
                    break

            if stop:
                break 
        
        # await bogus_response()
        stop_robot()
        time.sleep(1.5)
            
# Record responses for [south]
async def record_south():
    global secure_responses
    global BOUND
    
    for n in range(2, BOUND, 2):
        time.sleep(1.5)
        start_robot()
        
        proxying = True
            
        while True:
            messages = receive_radio_messages()
            stop = False
            for msg in messages:  
                if proxying and msg['dst'] == ME:
                    msg['dst'] = CONTROLLER     
                    print_pkt(msg)
                    inject_radio_message(msg)
                elif msg['dst'] == ROBOT:
                    print_pkt(msg)
                    
                # We drop all messages from the robot. This is just used as a anchor point so we know that it has validated properly
                if msg['msg_type'] == 'ack_key_exchange' and msg['dst'] == ROBOT:
                    proxying = False
                
                    # secure_data -> secure_data_request offsets the movement to south
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data', 0, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data_request', 1, CONTROLLER, None)
                    
                    # this peforms the rest of the offset
                    await asyncio.sleep(0.02)
                    await offset(2, n, 'south')
                    
                    stop = True
                    break

            if stop:
                break 
        
        # await bogus_response()
        stop_robot()
        time.sleep(1.5)

# Record responses for [west]
async def record_west():
    global secure_responses
    global BOUND
    
    for n in range(4, BOUND, 2):
        time.sleep(1.5)
        start_robot()
        
        proxying = True
            
        while True:
            messages = receive_radio_messages()
            stop = False
            for msg in messages:  
                if proxying and msg['dst'] == ME:
                    msg['dst'] = CONTROLLER     
                    print_pkt(msg)
                    inject_radio_message(msg)
                elif msg['dst'] == ROBOT:
                    print_pkt(msg)
                    
                # We drop all messages from the robot. This is just used as a anchor point so we know that it has validated properly
                if msg['msg_type'] == 'ack_key_exchange' and msg['dst'] == ROBOT:
                    proxying = False
                
                    # secure_data -> secure_data_request offsets the movement to south
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data', 0, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data_request', 1, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data', 2, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data_request', 3, CONTROLLER, None)
                    
                    # this peforms the rest of the offset
                    await asyncio.sleep(0.02)
                    await offset(4, n, 'west')
                    
                    stop = True
                    break

            if stop:
                break 
        
        # await bogus_response()
        stop_robot()
        time.sleep(1.5)

# Record responses for [north]
async def record_north():
    global secure_responses
    global BOUND
    
    for n in range(6, BOUND, 2):
        time.sleep(1.5)
        start_robot()
        
        proxying = True
            
        while True:
            messages = receive_radio_messages()
            stop = False
            for msg in messages:  
                if proxying and msg['dst'] == ME:
                    msg['dst'] = CONTROLLER     
                    print_pkt(msg)
                    inject_radio_message(msg)
                elif msg['dst'] == ROBOT:
                    print_pkt(msg)
                    
                # We drop all messages from the robot. This is just used as a anchor point so we know that it has validated properly
                if msg['msg_type'] == 'ack_key_exchange' and msg['dst'] == ROBOT:
                    proxying = False
                
                    # secure_data -> secure_data_request offsets the movement to south
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data', 0, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data_request', 1, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data', 2, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data_request', 3, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data', 4, CONTROLLER, None)
                    await asyncio.sleep(0.02)
                    await inject_packet('secure_data_request', 5, CONTROLLER, None)
                    
                    # this peforms the rest of the offset
                    await asyncio.sleep(0.02)
                    await offset(6, n, 'north')
                    
                    stop = True
                    break

            if stop:
                break 
        
        # await bogus_response()
        stop_robot()
        time.sleep(1.5)
        
asyncio.run(record_east())
asyncio.run(record_south())
asyncio.run(record_west())
asyncio.run(record_north())

stop_robot()
receive_radio_messages()
time.sleep(5)
### PART 3 -> SEND SECURE_DATA_REQUEST N - 1 TIMES, THEN SEND SECURE_DATA, THEN SEND SECURE_DATA_REQUEST, THEN RECORD SECURE_DATA_RESPONSE

# We can then forge responses!
### PART 4 -> FORGE
print('-' * 20 + 'Begin part 4')

nonce = 0

# targetpath = ["east", "south", "east", "north", "west", "south", "east", "north", "east", "south", "stop"]

target_path = [
    None, None, None, 'east', 
    None, 'south', 
    None, 'east',
    None, 'north',
    None, 'west',
    None, 'south',
    None, 'east',
    None, 'north',
    None, 'east',
    None, 'south'
]

async def exploit():
    global nonce 
    global target_path 
    
    print(target_path)
    
    start_robot()

    while True:
        messages = receive_radio_messages()
            
        for msg in messages:
            print_pkt(msg)
                
            if msg['dst'] == ME:
                if msg['msg_type'] == 'secure_data':
                    print('Received SDATA / Sending Bogus SDACK')
                    await bogus_ack()
                elif msg['msg_type'] == 'secure_data_request':
                    if len(target_path) > nonce:
                        await inject_packet('secure_data_response', nonce, ROBOT, target_path[nonce])
                        nonce += 1
                    else:
                        print('Finished target path, quitting!')
                        bogus_response()
                else:
                    msg['dst'] = CONTROLLER     
                    print_pkt(msg)
                    inject_radio_message(msg)
                            
                            
asyncio.run(exploit())
```

## Flag

![flag](/images/ricochetsolve.png)