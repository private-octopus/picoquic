

<!-- This version of the client and server use multipath. 

In `client.cpp`:
<ul>
  <li>
      line 38: provide server ip
  </li>
    <li>
      line 211: provide server ip
  </li>
    <li>
      line 212: provide your extra ip for the secondary interface
  </li>
</ul>

The primary interface is used to setup the connection, so picoquic already knows about that path and ip. You need to provide it the extra ip and path information. -->
