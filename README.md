# netseg
A python script that performs a TCP network scan of open ports for a given network. The script also outputs the results into a file which can be configured to detect whether a new port has been opened for any discovered systems.

## Usage/ Options

```bash
python netseg.py 
  -t 192.168.1.0/24 #[target in CIDR notation] 
  -p 22,80,443,8080 #[ports to scan]
```
