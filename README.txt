SPP - Synthetic Packet Pairs - 0.3.X - Readme

  1. Overview

        Regular and frequent measurement of round trip time (RTT) between points
        on the Internet is becoming increasingly important for a range of highly
        interactive real-time applications. Active probing techniques are
        possible but problematic. The extra packet traffic imposed by active
        probes along a network path can modify the behaviour of the network
        under test. In addition, estimated RTT results may be misleading if the
        network handles active probe packets differently to regular IP packets.

        In contrast, Synthetic Packet Pairs (SPP [1][2]) provides frequently 
        updated RTT estimates using IP traffic already present in the network. 
        SPP estimates the RTT between two measurement points without requiring
        precise time synchronisation between each point. SPP estimates the RTT 
        experienced by an application's traffic without needing modifications to
        the application itself or the routers along the path. In addition, SPP 
        works with applications that do not exhibit symmetric client-server 
        packet exchanges (such as many online multiplayer games) and 
        applications generating IP multicast traffic.

        This software is a flexible, standalone packet processor that implements
        the SPP algorithm. RTT calculations can be generated from saved PCAP
        format files or local or remote interfaces in real time.

  2. Installation

        Please see INSTALL.txt found in this directory.


  3. Definitions

        RTT is the round trip time that Target Traffic experiences between two 
        Measurement Points.

        A Measurement Point is an interface (or tap on the network) at which
        Target Traffic is observed. The two measurement points are REF (reference)
        and MON (monitor).
        
        Target Traffic consists of a user nominated subset of traffic made up of
        packets passing REF on the way towards MON, and packets flowing past MON
        on the way towards REF.
        
        SPP identifies target traffic using two IP addresses. The REF point IP address
        is the source address of target traffic packets heading in the REF to MON
        direction, while the MON point IP address represents a source of target
        traffic packets heading in the MON to REF direction.
        
        Packet pairs are constructed by pairing up a packet seen heading from REF
        to MON with the next packet seen heading the other way from MON to REF.


  4. Operation

        SPP estimates RTT between two measurement points along a network path.
        Traffic is observed at both measurement points, and the RTT
        between the two measurement points is estimated from pairs of
        packets seen travelling in each direction.

        Data can be collected from measurement points in two ways. The simplest
        method is for the user to collect data at both monitor points manually
        before running SPP. This can be achieved using tcpdump on the
        measurement point interface. SPP can then read these PCAP files to
        estimate RTT. Of course this method can only provide retrospective
        RTT estimates.

        Alternatively, when near real time RTT estimates are required, SPP can
        passively monitor live network interfaces. Generally, the two
        measurement points are geographically separate, requiring SPP to be run
        on two separate hosts. The most common setup for near real time
        measurements involves an 'SPP master' and 'SPP slave'. At one measurement
        point, SPP is run as the master. At this point, SPP actually processes
        the data and outputs RTT estimates. At the other measurement point, SPP
        is run as a slave. It simply observes data and sends relevant 
        information to the SPP master. The relevant information in conveyed with
        SPP Sample Frames (SSF). These are UDP packets which contain enough 
        information to reconstruct IDs of observed packets and their 
        corresponding timestamps.

        (NOTE: Live remote monitoring is still experimental and may have bugs)

        In this implementation, target traffic is specified as packets flowing
        between two hosts. IP addresses of these hosts must be entered on
        the command line. The path between these two hosts must pass by the two
        measurement points. It may be that the measurement points reside on the
        hosts generating the target traffic, but this is not required.

  5. SPP Command Syntax and Options

        USAGE: File processing:
        spp -a address -A address -f file -F file [-# <hashcode> |-p|-c|-m|-b|-O|-P]


        USAGE: Live processing master:
        spp -a address -A address (-i interface | -r host )
        ( -I interface | -R slave_host ) [-# <hashcode> |-g usec |-p|-c|-m|-b|-O|-P]

        USAGE: Remote slave:
        spp  -a  address -A address -s master_host -I interface 
        [ -# <hashcode> | -g usec | -l no.bytes | -t seconds ]


      General Options:
        -a IP address at the reference point
        -A IP address at the monitor point
        -n Natted IP address of the reference point
        -N Natted IP address of the monitor point
        -s Put into slave mode and send SSF to specified host
        -v Verbosity Level - see man page
        -d T Delta Maximum (seconds) (default: 60)
        -o Offset in seconds of the monitor point with respect to the reference point
	-G Search interval in number of packets (default: 10000(file)/500(live))
        -P Enable pcap/bpf filtering (only accept DLT_EN10MB-framed packets where IP addresses match)

       Source options:
        -f File to be read for the reference point (PCAP format)
        -F File to be read for the monitor point (PCAP format)
        -i Reference point live capture interface
        -I Monitor point live capture interface

       Network Options:
        -l Length of remotely measured timestamps in bytes (default: 2)
        -g Granularity of remotely measured timestamps in microseconds (default: 100)
        -t Timeout - max time in seconds between updates from slave

       Output options:
        -p Output 'Server Processing Times'
        -c Output 'Pair Count'
        -m Calculate timestamps from monitor point clock
        -b Use the timestamp of the first packet in the pair for the pair timestamp

        Packet Matching Options:
        -# <hashcode> (default: 63)
        The # option maybe used to set which fields are used in the packet matching process.
        The value of <hashcode> is the total of all the required field IDs as listed below:
        
        IP fields:
                        1 Source Address
                        2 Destination Address
                        4 Protocol
                        8 Identification
        TCP/UDP fields:
                        16 Source Port
                        32 Destination Port
        TCP fields:
                        64 Sequence Number
                        128 Acknowledgement Number
                        256 Data offset, flags, window size
                        512 Checksum, urgent pointer
                        8192 Up to 12 bytes of TCP payload (limited by packet length)
                        16384 All TCP Options bytes (if present)
        UDP Fields:
                        1024 Length, checksum
                        2048 Up to 12 bytes UDP data (limited by packet length)
        Not UDP/TCP:
                        4096 Up to 20 bytes after IP header (limited by packet length)


        NOTE: IP addresses will not be used for hashing when NAT is in use.

  6. Packet identification and clocks 
  
   6.1 Packet identification
   
        A crucial step in pairing packets is identifying each packet seen at REF
        with the same packet seen at MON (separately in each direction). SPP does
        this by generating a per-packet hash across a number of fields in the
        IP header, transport protocol header and/or payload. The '-#' option
        controls what specific combination of fields are used to generate the hash.
        
        Reliable disambiguation of packets requires hashing over fields that
        vary from one packet to the next, yet are invariant between REF and MON
        (not altered by network devices along the path). Some problematic scenarios
        include NAT (where IP addresses are not invariant along a path, and
        TCP/UDP ports may also be altered) and TCP sequence number remapping
        (observed being performed by certain 'security' middleboxes).
        
        When SPP was first developed, the IP.ID field was often unique for
        every IP packet emitted by a sender, and could be relied on to disambiguate
        retransmissions of higher later segments. However, RFC 6864 has formalised
        the notion that IP.ID need only be unique for fragments of a larger IP packet.
        
        The TCP Option bytes are useful for disambiguating TCP packets (including
        retransmissions) where the underlying connections have negotiated (and
        correctly use) the Time Stamp option. In such cases, retransmissions will
        always differ by their TSval field.
        
        If you find spp is generating implausibly high RTTs from time to time (such as
        when the hash fails to disambiguate a retransmitted TCP segment at MON from its
        orignal seen at REF), use a custom "-# <hashcode>" to hash over additional fields.

        If you find spp is not generating RTT estimates, use a custom "-# <hashcode>" to
        hash over fewer fields. (For example, don't hash over TCP sequence or acknowledgement
        numbers if a middle-box is rewriting these fields mid-path. Otherwise spp will
        fail to match a packet seen at REF with the same packet seen at MON.)
        
   6.2 Clock Synchronisation

        The SPP algorithm does not strictly require clocks at REF and MON to be
        synchronised. Nevertheless, this SPP implementation applies a practical
        limit on how far forward and back in time it searches to match packets
        captured at REF and MON monitoring points. By default, your REF and MON
        clocks ought to be synchronised to within 60 seconds (this can be altered
        with the '-d' option). If you find SPP is not generating  estimates, it
        may be due to excessive offset between the REF and MON system clocks.

        If you know that your sources have a fixed time offset, SPP can take this 
        into account. The known offset can be specified in seconds using the
        '-o' option, where the value refers to the offset at MON relative to REF.

        In addition, the option '-d' can be used to alter the maximum tolerance
        (in seconds) for clocks that are out of sync. See [2] for more details
        on 'T delta'.

  7. Usage Examples

        It is recommended that you familiarise yourself with the usage 
        examples below and visit http://www.caia.swin.edu.au/tools/spp/ to view 
        more comprehensive usage information with diagrams.

        The examples 7.1 to 7.4 assume the measurement points reside on the
        hosts generating the target traffic. Examples 7.5 and 7.6 show
        examples where the measurement points are on separate hosts.

   7.1 From files
   
       The  IP  at  the  reference point is 10.0.0.1 and the IP at the monitor
       point is 10.0.0.2. The files /data/ref.pcap and /data/mon.pcap  contain
       data observed at the reference and monitor points respectively. Note
       that the display of pair count and server  processing  times  are  also
       enabled:

       spp -f /data/ref.pcap -a 10.0.0.1 -F /data/mon.pcap -A 10.0.0.2 -cp


   7.2 Local live observation
   
       Processing  RTT  in rear real time from two local interfaces. This would
       be useful in a lab environment  when  testing  equipment  or  networks.
       There are two local interfaces (em0 and em1) with IP addresses 10.0.1.1
       and 10.0.2.1 respectively. The reference point will be em0  (10.0.1.1).

       spp -i em0 -a 10.0.1.1 -I em1 -A 10.0.2.1


   7.3 Local/Remote with in band SSF transmission
   
       Processing RTT in near real time from a local interface at the reference
       point and remote interface at the monitor point. This example uses in
       band SSF transmission.

       The  master  is  running at the reference point and is capturing on the
       interface em0 (Interface address 10.0.0.1). The slave is running at the
       monitor  point,  capturing  on  the  bge0  interface (Interface address
       10.0.0.2).

       On the master:

       spp -i em0 -a 10.0.0.1 -R 10.0.0.2 -A 10.0.0.2

       On the slave:

       spp -s 10.0.0.1 -a 10.0.0.1 -I bge0 -A 10.0.0.2


   7.4 Local/Remote with out of band SSF transmission
   
       Processing RTT in near real time from a local interface at the reference
       point and remote interface at the monitor point. This example uses out
       of band SSF transmission.

       This is the same as the previous example except that the hashes will be
       sent  across  a  separate network to that which is being measured. The
       interfaces to  this  network  have  IP  addresses  of  192.168.0.1  and
       192.168.0.2 at the reference and monitor points respectively.

       On the master:

       spp -i em0 -a 10.0.0.1 -R 192.168.0.2 -A 10.0.0.2

       On the slave:

       spp -s 192.168.0.1 -a 10.0.0.1 -I bge0 -A 10.0.0.2

   7.5 From files (With target traffic hosts separate from measurement points)
   
       The  IP  at  the  reference point is 10.0.0.1 and the IP at the monitor
       point is 10.0.0.2. The files /data/ref.pcap and /data/mon.pcap  contain
       data observed at the reference and monitor points respectively.
       Target traffic was generated by the hosts 10.1.0.1 and 10.2.0.1 which
       lie on networks either side of the measurement points.

       spp -a 10.1.0.1 -A 10.2.0.1 -f /data/ref.pcap -F /data/mon.pcap -cp

   7.6 Local/Remote (Target traffic hosts separate from measurement points)
   
       Processing RTT in near real time from a local interface at the reference
       point and remote interface at the monitor point. Target traffic was
       generated by the hosts 10.1.0.1 and 10.2.0.1 which lie on networks either
       side of the measurement points.

       The  master  is  running at the reference point and is capturing on the
       interface em0 (Interface address 10.0.0.1). The slave is running at the
       monitor  point,  capturing  on  the  bge0  interface (Interface address
       10.0.0.2).

       On the master:

       spp -i em0 -a 10.1.0.1 -A 10.2.0.1 -R 10.0.0.2 

       On the slave:

       spp -a 10.1.0.1 -A 10.2.0.1 -s 10.0.0.1 -I bge0 

  8. References

   [1]    S. Zander, G. Armitage, T. Nguyen,L. Mark, B. Tyo
          "Minimally Intrusive Round Trip Time Measurements Using
          Synthetic Packet-Pairs," CAIA Technical Report 060707A, July 2006.
          http://caia.swin.edu.au/reports/060707A/CAIA-TR-060707A.pdf
          
   [2]    S. Zander, G. Armitage, "Minimally-Intrusive Frequent Round Trip
          Time Measurements Using Synthetic Packet-Pairs - Extended Report",
          CAIA Technical Report 130730A, July 2013
          http://caia.swin.edu.au/reports/130730A/CAIA-TR-130730A.pdf
          
          
          