# WireShark

One of the most powerful tool available in the wild. 
- Troubleshoot network problems
- Detect security anomalies (rogue host, abnormal port usage, suspicious traffic)
- Learning protocols details

# Overview 

### GUI and Data

***At the beginning, five sections stand out***  
|Section|Description|
|:------|:----------|
Toolbar |	The main toolbar contains multiple menus and shortcuts for packet sniffing and processing, including filtering, sorting, summarising, exporting and merging. 
Display Filter Bar	|The main query and filtering section.
Recent Files	|List of the recently investigated files. You can recall listed files with a double-click. 
Capture Filter and Interfaces	|Capture filters and available sniffing points (network interfaces).  The network interface is the connection point between a computer and a network. The software connection (e.g., lo, eth0 and ens33) enables networking hardware.
Status Bar	Tool |status, profile and numeric packet information.

***When a pcap file is opened, three other sections stand out***  
|Section|Description|
|:------|:----------|
Packet List Pane | Summary of each packet (source and destination addresses, protocol, and packet info). You can click on the list to choose a packet for further investigation. Once you select a packet, the details will appear in the other panels.
Packet Details Pane | Detailed protocol breakdown of the selected packet.
Packet Bytes Pane | Hex and decoded ASCII representation of the selected packet. It highlights the packet field depending on the clicked section in the details pane.   

***Packer colors***  
Wireshark colours packets in order of different conditions and protocols to spot anomalies  
Wireshark has two type of colouring
- Temporary rules that are only available during a program session 
	- View -> Conversation Filter
- Permanent rules that are saved under the preference file
	- View -> Colourise packet list

### Traffic sniffing
The blue shark button (top left) will start sniffing process

### Merge PCAP files

Wireshark can combine two pcap files into a single one
	- File -> Merge
Note : You need to save the merged pcap file before working on it

### View File Details

Knowing the file details is helpful. 
- File hash
- capture time
- capture file comments
- interface and statistics
	- Statistics --> Capture File Properties

# Packet Dissection
Investigates packet details by decoding available protocols and fields  
Many protocols are supported for dissection  
Note : we can write our dissection scripts  

***Packets consist of 5 to 7 layers based on the OSI model***
Each of these are one line in the bottom left tab

### Layer 1 : The Frame (physical)
This will show you what frame/packet you are looking at and details specific to the Physical layer of the OSI model.  

### Layer 2 : The Source [MAC] (data link)
This will show you the source and destination MAC Addresses

### Layer 3 : The Source [IP] (network)
This will show you the source and destination IPv4 Addresses

### Layer 4 : Protocol (transport)
This will show you details of the protocol used (UDP/TCP) and source and destination ports  
***Layer 4 : Protocol errors***  
This continuation of the 4th layer shows specific segments from TCP that needed to be reassembled.

### Layer 5 : Application Protocol
This will show details specific to the protocol used, such as HTTP, FTP, and SMB.  
***Layer 5 : Application data*** 
This extension of the 5th layer can show the application-specific data

# Packet Navigation

Tips : CTRL+G to select a packet id and go through it

***Search content***  
Wireshark can find packet from their content
	- Edit -> Find Packet
This functionality accepts four types of inputs (Display filter, Hex, String and Regex)  

***Mark packets***  
Wireshark allow us to mark and retrieve marked packets
	- File -> Mark (and all variations)
Note : Marked packets will be displayed in black
Note : Marked packet will not be stored from a session to an other one

***Comment packets***  
Wireshark allow us to comment packets  
	- Edit -> Packet comment
Note : Comments can be stored in the pcap file and be retrieves from a session to another
Note : Comment are chown above the Frame section in the bottom left corner  

***Export packets***  
Since Wireshark is not an IDS (Intrusion Detection System), it is relevant to export packet somewhere else to investigate it  
	- File -> Export (and variations)

***Extract object (Files)***  
Wireshark can extract files transferred through the wire.  
Only available for selected protocol's streams (DICOM, HTTP, IMF, SMB and TFTP).

***Time Display Format***  
By default, Wireshark display the time "in seconds since beginning of capture"  
But the common usage is using the UTC Time Display Format
	- View -> Time Display Format

***Expert info***  

Accessible via the lil red dot at the extreme botom left corner

Severity | Colour | Info
|:-|:-|:-|
Chat | Blue | Information on usual workflow.
Note | Cyan | Notable events like application error codes.
Warn | Yellow | Warnings like unusual error codes or problem statements.
Error | Red | Problems like malformed packets.
# Packet Filtering
Wireshark has two types of filtering approaches: capture and display filters.   
- Capture filters are used for "capturing" only 
- Display filters are used for "viewing" the 

***Apply as Filter***  
This is the most basic way of filtering traffic  
You can click on the field you want to filter and use the "right-click menu"

***Conversation Filter***  
Suppose you want to investigate a specific packet number and all linked packets by focusing on IP addresses and port numbers.

***Colourise Conversation***  
Highlights the linked packets without applying a display filter 
Note : use the "View --> Colourise Conversation --> Reset Colourisation

***Prepare as Filter***  
Similar to "Apply as Filter", however, unlike the previous one, this model doesn't apply the filters after the choice. It adds the required query to the pane and waits for the execution command (enter)

***Apply as Column***  
You can use the "right-click menu" or "Analyse -->  Apply as Column" menu to add columns to the packet list pane.

***Follow Stream***  
It is possible to reconstruct the streams and view the raw traffic as it is presented at the application level. Following the protocol, streams help analysts recreate the application-level data and understand the event of interest.   