

# Server side sniffer

> Tool that captures all packets between the client and services, and between the services themselves. The user can start an **action** which will sniff all packets and save them to one or more **pcap** files while the action is ongoing. 

 

#### Default ports for 2016 services. 

| Service     | ALL  | Client | Zone | w_Manager |
| ----------- | ---- | ------ | ---- | --------- |
| Login       |      | 9010   |      | 9011      |
| w_Manager_0 |      | 9110   | 9111 |           |
| Zone_0      |      | 9210   | 9218 |           |
| Zone_1      |      | 9212   | 9219 |           |
| Zone_2      |      | 9214   | 9220 |           |
| Zone_3      |      | 9216   | 9221 |           |
| Zone_4      |      | 9218   | 9222 |           |
| AccountLog  | 9311 |        |      |           |
| Character   | 9411 |        |      |           |
| GameLog     | 9511 |        |      |           |



#### Development goals. 



- App will capture packets flowing between two ports:

  -  **e.g :** **Client**  and **Login**
  - **e.g :**  **Client**  and **AccountLog**
  - **e.g:**   **Client** and **Character**
  - **e.g:**   **Client** and **GameLog**
  - **e.g:**   **Client** and **Zones 0, 1, 2, 3, 4**
  - ... etc 

- App will save a ncap file for each flow. 

  - **e.g:** client_login_12000.pcap

  - **e.g:** login_client_12001.pcap

    





