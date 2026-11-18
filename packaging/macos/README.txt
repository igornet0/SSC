SSC VPN for macOS

Install
  1. Open "Install SSC.pkg" (enter your Mac password once)
  2. The installer grants passwordless TUN rights — Connect will not ask again
  3. After install, use Terminal:

       ssc add 'vless://…'
       ssc connect --best
       ssc status
       ssc disconnect

  Check privileges:  ssc privileges status

Uninstall
  • Double-click "Uninstall SSC.command"
  • Or run:  sudo ssc-uninstall
  • With data wipe:  sudo ssc-uninstall --purge
