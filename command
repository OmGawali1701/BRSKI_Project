mosquitto_sub -h 10.182.3.33 -p 8883 --cafile D:\Shared_Folder\windows_required_cert_files\ca.crt --cert D:\Shared_Folder\windows_required_cert_files\client.crt --key D:\Shared_Folder\windows_required_cert_files\client.key --tls-version tlsv1.2 -t "device/data" 

mosquitto_pub -h 10.182.3.33 -p 8883 --cafile /home/om/cert/ca.crt -t device/data -m "Linux publishing to Windows broker"
