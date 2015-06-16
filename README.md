# flog
This program is meant to take input from stdin and produce a human readable output for analysis. 

Future expansion will bring the ability to choose which fields to display.

## Example
### Before:
$ head -5 ~/test-fw 

Jun 16 06:54:17 test-fw 1 2015-06-16T03:54:16.444-07:00 test-fw-1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.39 source-address="10.10.30.6" source-port="51295" destination-address="10.32.128.191" destination-port="443" service-name="junos-https" nat-source-address="10.10.30.6" nat-source-port="51295" nat-destination-address="10.32.128.191" nat-destination-port="443" src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="6" policy-name="11000" source-zone-name="DMZ-VPN" destination-zone-name="DMZ" session-id-32="14036" username="N/A" roles="N/A" packet-incoming-interface="st0.21" application="UNKNOWN" nested-application="UNKNOWN" encrypted="UNKNOWN"] session created 10.10.30.6/51295->10.32.128.191/443 junos-https 10.10.30.6/51295->10.32.128.191/443 None None 6 11000 DMZ-VPN DMZ 14036 N/A(N/A) st0.21 UNKNOWN UNKNOWN UNKNOWN

Jun 16 06:54:17 test-fw 1 2015-06-16T03:54:16.446-07:00 test-fw-1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.39 source-address="10.34.1.170" source-port="52650" destination-address="10.43.2.83" destination-port="80" service-name="junos-http" nat-source-address="12.8.241.2" nat-source-port="63314" nat-destination-address="10.43.2.83" nat-destination-port="80" src-nat-rule-name="internet-snat" dst-nat-rule-name="None" protocol-id="6" policy-name="dmz-to-internet" source-zone-name="DMZ" destination-zone-name="INTERNET" session-id-32="499602" username="N/A" roles="N/A" packet-incoming-interface="reth2.0" application="UNKNOWN" nested-application="UNKNOWN" encrypted="UNKNOWN"] session created 10.34.1.170/52650->10.43.2.83/80 junos-http 12.8.241.2/63314->10.43.2.83/80 internet-snat None 6 dmz-to-internet DMZ INTERNET 499602 N/A(N/A) reth2.0 UNKNOWN UNKNOWN UNKNOWN

Jun 16 06:54:17 test-fw 1 2015-06-16T03:54:16.446-07:00 test-fw-1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.39 source-address="10.10.30.6" source-port="37180" destination-address="10.32.128.191" destination-port="80" service-name="junos-http" nat-source-address="10.10.30.6" nat-source-port="37180" nat-destination-address="10.32.128.191" nat-destination-port="80" src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="6" policy-name="11000" source-zone-name="DMZ-VPN" destination-zone-name="DMZ" session-id-32="459036" username="N/A" roles="N/A" packet-incoming-interface="st0.21" application="UNKNOWN" nested-application="UNKNOWN" encrypted="UNKNOWN"] session created 10.10.30.6/37180->10.32.128.191/80 junos-http 10.10.30.6/37180->10.32.128.191/80 None None 6 11000 DMZ-VPN DMZ 459036 N/A(N/A) st0.21 UNKNOWN UNKNOWN UNKNOWN

Jun 16 06:54:17 test-fw 1 2015-06-16T03:54:16.497-07:00 test-fw-1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.39 source-address="10.10.30.6" source-port="53766" destination-address="10.32.128.191" destination-port="22" service-name="junos-ssh" nat-source-address="10.10.30.6" nat-source-port="53766" nat-destination-address="10.32.128.191" nat-destination-port="22" src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="6" policy-name="11000" source-zone-name="DMZ-VPN" destination-zone-name="DMZ" session-id-32="30512" username="N/A" roles="N/A" packet-incoming-interface="st0.21" application="UNKNOWN" nested-application="UNKNOWN" encrypted="UNKNOWN"] session created 10.10.30.6/53766->10.32.128.191/22 junos-ssh 10.10.30.6/53766->10.32.128.191/22 None None 6 11000 DMZ-VPN DMZ 30512 N/A(N/A) st0.21 UNKNOWN UNKNOWN UNKNOWN

Jun 16 06:54:17 test-fw 1 2015-06-16T03:54:16.595-07:00 test-fw-1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.39 source-address="10.10.30.6" source-port="53767" destination-address="10.32.128.191" destination-port="22" service-name="junos-ssh" nat-source-address="10.10.30.6" nat-source-port="53767" nat-destination-address="10.32.128.191" nat-destination-port="22" src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="6" policy-name="11000" source-zone-name="DMZ-VPN" destination-zone-name="DMZ" session-id-32="157300" username="N/A" roles="N/A" packet-incoming-interface="st0.21" application="UNKNOWN" nested-application="UNKNOWN" encrypted="UNKNOWN"] session created 10.10.30.6/53767->10.32.128.191/22 junos-ssh 10.10.30.6/53767->10.32.128.191/22 None None 6 11000 DMZ-VPN DMZ 157300 N/A(N/A) st0.21 UNKNOWN UNKNOWN UNKNOWN

### After:
$ head -5 ~/test-fw | flog.py 
permit              10.10.30.6       10.32.128.191    443     TCP   DMZ-VPN              DMZ                  st0.21             11000

permit              10.34.1.170      10.43.2.83      80      TCP   DMZ                  INTERNET             reth2.0            dmz-to-internet

permit              10.10.30.6       10.32.128.191    80      TCP   DMZ-VPN              DMZ                  st0.21             11000

permit              10.10.30.6       10.32.128.191    22      TCP   DMZ-VPN              DMZ                  st0.21             11000

permit              10.10.30.6       10.32.128.191    22      TCP   DMZ-VPN              DMZ                  st0.21             11000
