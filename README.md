# gnmap_transmorgify

    usage: gnmap_transmorgify.py [-h] [-g GREP] [-K] [-s STATUS]
                                 [-p {tcp,udp,any}] [-d {must,try,never}] [-u]
                                 [-f {plain,url}]
                                 PATH
    
    Transmorgify nmap greppable results
    
    positional arguments:
      PATH                  path for .gnmap file to transmorgify
    
    optional arguments:
      -h, --help            show this help message and exit
      -g GREP, --grep GREP  search nmap results for term
      -K, --case-sensitive  turn on case sensitivity
      -s STATUS, --status STATUS
                            show ports that have status STATUS i.e. open, closed
                            etc
      -p {tcp,udp,any}, --protocol {tcp,udp,any}
                            show ports with protocol
      -d {must,try,never}, --domain {must,try,never}
                            when to use domain names over IPs
      -u, --urls            extract urls
      -f {plain,url}, --factory {plain,url}
                            force object factory

