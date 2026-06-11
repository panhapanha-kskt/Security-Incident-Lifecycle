Start-Sleep -Seconds 60
$WSL_IP = (wsl hostname -I).Split()[0]
netsh interface portproxy delete v4tov4 listenport=8443 listenaddress=0.0.0.0
netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=8443 connectaddress=$WSL_IP
wsl -e bash -c "cd /home/Panha/wazuh-project/docker/prod1-thehive && docker-compose up -d"
