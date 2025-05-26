#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <malloc.h>
#include <mosquitto.h>

#define BUF_SIZE 1024

#define DATA_FILE "/tmp/Behavioral_Attributes_data.json"
#define TOPIC     "device/data"
#define BROKER    "localhost"

FILE *json = NULL; 
struct mosquitto *mosq = NULL;

int  log_uptime();
int  log_cpu_usage();
//int  log_cpu_temp();
int  log_network_traffic();
int  log_memory_usage();
int  log_disk_usage();

int mqtt_publish_initialisation();
void mqtt_publish();

int main() 
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  fprintf(stdout, "Program Stareted\n");
  json = fopen("/tmp/Behavioral_Attributes_data.json","w+");
    if(!json)
    {
      perror("Could not create or open /tmp/Behavioral_Attributes_data.json");
      return -1;
    }
  
  mqtt_publish_initialisation();
      
  while (1) 
    {
        
        ftruncate(fileno(json), 0);    
        fseek(json, 0, SEEK_SET);  
        
        
        fprintf(json, "{\n");
        
        log_uptime();
        log_cpu_usage();
    //  log_cpu_temp();
        log_memory_usage();
        log_disk_usage();
        
        fprintf(json, "}\n");
        fflush(json);
      
        mqtt_publish();

        sleep(15);
    }
    fclose(json);
    fprintf(stdout, "File Closed \"/tmp/Behavioral_Attributes_data.json\"\n");
    
    mosquitto_disconnect(mosq);
    fprintf(stdout, "MQTT Broker Disconnected\n");
    
    mosquitto_destroy(mosq);
    fprintf(stdout, "Mosquitto Instance Destroyed\n");    
    
    mosquitto_lib_cleanup();
    fprintf(stdout, "Mosquitto Lib Cleared\n");
}

int log_uptime() 
{
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) 
    {
      fprintf(stderr, "Could not open /proc/uptime\n");
      perror("Could not open /proc/uptime");
      return -1;
    }
    double uptime;
    fscanf(fp, "%lf", &uptime);
    fprintf(json,"\t\"uptime\":\"%lf\",\n",uptime);
    fflush(json);
    fclose(fp);
    
}

int log_cpu_usage() 
{
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) 
    {
      fprintf(stderr, "Could not open /proc/stat\n");    
      perror("Could not open /proc/stat");
      return -1;
    }
    char * buffer = (char *)calloc(BUF_SIZE,sizeof(char));
    if (!buffer)
    {
        perror("Memory allocation failed");
        fclose(fp);
        return -1;
    }
    fgets(buffer, BUF_SIZE, fp);
    unsigned long long int user, nice, system, idle;
    sscanf(buffer, "cpu %llu %llu %llu %llu", &user, &nice, &system, &idle);
    fclose(fp);
    fprintf(json,"\t\"CPU_User_Time\":\"%llu\",\n",user);
    fprintf(json,"\t\"CPU_System_Time\":\"%llu\",\n",system);
    fprintf(json,"\t\"CPU_Idle_Time\":\"%llu\",\n",idle); 
    fflush(json);
    free(buffer);
}
/*
int log_cpu_temp() 
{
    FILE *fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (!fp) 
    {
      perror("Could not open /sys/class/thermal/thermal_zone0/temp");
      return -1;
    }
    int temp;
    fscanf(fp, "%d", &temp);
    fclose(fp);
    fprintf(json,"\t\"CPU_Temperature_(°C)\":\"%.2f\",\n",temp / 1000.0);
    fflush(json);
}
*/
int log_network_traffic() 
{
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) 
    {
      fprintf(stderr, "Could not open /proc/net/dev\n");
      perror("Could not open /proc/net/dev");
      return -1;
    }
    char * buffer = (char *)calloc(512,sizeof(char));
    if (!buffer)
    {
        perror("Memory Allocation Failed");
        fclose(fp);
        return -1;
    }
    for(int i = 0; i < 2; i++) 
      fgets(buffer, 512, fp); // Skip headers
    while (fgets(buffer, 512, fp))
    {
        char iface[16];
        unsigned long rx_bytes, tx_bytes;
        if (sscanf(buffer, "%15s %lu %*s %*s %*s %*s %*s %*s %*s %lu", iface, &rx_bytes, &tx_bytes) == 3)
        {
            iface[strcspn(iface, ":")] = '\0'; // Safe colon removal
            fprintf(json, "\t\"Interface_%s_RX_(Bytes)\":\"%lu\",\n", iface, rx_bytes);
            fprintf(json, "\t\"Interface_%s_TX_(Bytes)\":\"%lu\",\n", iface, tx_bytes);
            fflush(json);
        }
    }
    free(buffer);
    fclose(fp);
}

int log_memory_usage() 
{ 
    struct sysinfo info;
    sysinfo(&info);
    struct mallinfo2 mi = mallinfo2();
    fprintf(json,"\t\"Total_Memory_(MB)\":\"%lu\",\n",info.totalram / (1024 * 1024));
    fprintf(json,"\t\"Free_Memory_(MB)\":\"%lu\",\n",info.freeram / (1024 * 1024));
    fprintf(json,"\t\"Used_Memory_(MB)\":\"%lu\",\n",(info.totalram - info.freeram) / (1024 * 1024));
    
    fprintf(json,"\t\"Used_Heap_Memory_(KB)\":\"%ld\",\n",mi.uordblks / 1024);
    fprintf(stdout, "Heap in KB: %ld\n", mi.uordblks / 1024);
    
    fflush(json);
}

int log_disk_usage() 
{
    struct statvfs fs;
    if (statvfs("/", &fs) == 0) 
    {
        unsigned long total = fs.f_blocks * fs.f_frsize / (1024 * 1024);
        unsigned long free = fs.f_bfree * fs.f_frsize / (1024 * 1024);
        unsigned long used = total - free;
        fprintf(json,"\t\"Disk_Total_(MB)\":\"%lu\",\n",total);
        fprintf(json,"\t\"Disk_used_(MB)\":\"%lu\",\n",used);
        fprintf(json,"\t\"Disk_free_(MB)\":\"%lu\"\n",free);
        fflush(json);
    }
}

int mqtt_publish_initialisation()
{
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);//  NULL = the client ID, true = client should automatically reconnect when connection is lost 
                                           //  NULL = user-defined object 
    if (!mosq) 
    {
        fprintf(stderr, "Failed To Create Mosquitto Instance\n");
        return -1;
    }
        fprintf(stdout, "Created Mosquitto Instance\n");

    if (mosquitto_connect(mosq, BROKER, 1883, 60) != MOSQ_ERR_SUCCESS) //mosq = name of client, BROKER = host name, 1883 = port no (Unsecure MQTT Port), 60 = keep-alive interval in sec 
    {
        fprintf(stderr, "Unable To Connect To MQTT Broker\n");
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return -1;
    }    
        fprintf(stdout, "Connected To MQTT Broker\n");
}

void mqtt_publish()
{
    fseek(json, 0, SEEK_SET);    
    char * buffer = (char *)calloc(BUF_SIZE, sizeof(char));
    if (!buffer) 
    {
      perror("Could not allocate memory to MQTT Buffer");
      return;
    }
    size_t buff_length = fread(buffer, 1, BUF_SIZE-1, json);
    buffer[buff_length]='\0';
    
    int rc = mosquitto_publish(mosq, NULL, TOPIC, strlen(buffer), buffer, 0, false);

    if (rc != MOSQ_ERR_SUCCESS) 
    {
      fprintf(stderr, "Failed to publish: %s\n", mosquitto_strerror(rc));
    }
    fprintf(stderr, "Data Published\n");
    free(buffer);

    /*
    NULL = message ID, TOPIC = messege categorised, strlen(buffer) = length of the message (bytes), buffer = actual message location, 0: The QoS (at most once), false: Retain flag off (will not retain the message after it is delivered)
    
    */
}    
