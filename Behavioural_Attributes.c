#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <malloc.h>
#include <mosquitto.h>
#include <signal.h>
#include <errno.h>

#define BUF_SIZE 1024
#define JSON_BUF_SIZE 2048

#define DATA_FILE "/tmp/Behavioural_Attributes_data.json"
#define TOPIC     "device/data"
#define BROKER    "localhost"

FILE *json = NULL; 
struct mosquitto *mosq = NULL;
volatile sig_atomic_t Keep_Running_Flag = 1;
volatile sig_atomic_t Exit_Signal_Flag = 0;
volatile sig_atomic_t Clean_Up_Flag = 0;
volatile sig_atomic_t Broker_Connection_Flag =0;
volatile sig_atomic_t Memory_Flag = 0;
volatile sig_atomic_t Json_File_Flag = 0;

void log_uptime();
void log_cpu_usage();
void log_cpu_temp();
void log_network_traffic();
void log_memory_usage();
void log_disk_usage();

void check_disk_space_or_exit();

void mqtt_publish_initialisation();
void mqtt_publish();

const char *get_signal_reason(int); 
void clean_up_resources();
void signal_handler(int);

int main() 
{
  fprintf(stdout, "Daemon running. PID: %d\n", getpid());

  atexit(clean_up_resources);
  
  signal(SIGINT,  signal_handler);  // Ctrl+C
  signal(SIGTERM, signal_handler);  // systemd or kill
  signal(SIGQUIT, signal_handler);  // Ctrl+\
  
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  
  check_disk_space_or_exit();

  json = fopen(DATA_FILE,"w+");
    if(!json)
    {
      Json_File_Flag = 1;
      fprintf(stderr,"Could not create or open %s: %s\nExiting.....\n",DATA_FILE,strerror(errno));
      exit(EXIT_FAILURE);
    }
  
  mqtt_publish_initialisation();
      
  while (Keep_Running_Flag) 
    {
        
        ftruncate(fileno(json), 0);    
        fseek(json, 0, SEEK_SET);  
        
        fprintf(json, "{\n");
        
        log_uptime();
        log_cpu_usage();
        log_cpu_temp();
        log_memory_usage();
        log_disk_usage();
        
        fprintf(json, "}\n");
        fflush(json);
      
        mqtt_publish();

        sleep(10);
    }
        clean_up_resources();
        return 0;

}

void log_uptime() 
{
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) 
    {
      fprintf(stderr,"Could not open /proc/uptime: %s\n",strerror(errno));
      fprintf(stdout,"Skipping Uptime read\n");
    }
    else
    {
    double uptime;
    fscanf(fp, "%lf", &uptime);
    fprintf(json,"\t\"uptime\":\"%lf\",\n",uptime);
    fflush(json);
    fclose(fp);
    }
    
}

void log_cpu_usage() 
{
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) 
    {
      fprintf(stderr,"Could not open /proc/stat: %s\n",strerror(errno));
      fprintf(stdout,"Skipping CPU Usage read\n");
    }
    else
    {
    char * buffer = (char *)calloc(BUF_SIZE,sizeof(char));
    if (!buffer)
    {
        fprintf(stderr,"Memory allocation failed: %s\n",strerror(errno));  
        fclose(fp);
    }
    else
    {
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
    }
}

void log_cpu_temp() 
{
    FILE *fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (!fp) 
    {
      fprintf(stderr, "Temperature sensor not found. Skipping Temp read : %s\n",strerror(errno));
      
    }
    else
    {
    int temp;
    fscanf(fp, "%d", &temp);
    fclose(fp);
    fprintf(json,"\t\"CPU_Temperature_(°C)\":\"%.2f\",\n",temp / 1000.0);
    fflush(json);
    }
}

void log_network_traffic() 
{
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) 
    {
      fprintf(stderr, "Could not open /proc/net/dev: %s\n",strerror(errno));
      fprintf(stdout,"Skipping Network Traffic read\n");
    }
    else
    {
    char * buffer = (char *)calloc(512,sizeof(char));
    if (!buffer)
    {
        fprintf(stderr, "Memory Allocation Failed: %s\n",strerror(errno));
    }
    else
    {
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
    }
    fclose(fp);
    }
}

void log_memory_usage() 
{ 
    struct sysinfo info;
    sysinfo(&info);
    struct mallinfo2 mi = mallinfo2();
    fprintf(json,"\t\"Total_Memory_(MB)\":\"%lu\",\n",info.totalram / (1024 * 1024));
    fprintf(json,"\t\"Free_Memory_(MB)\":\"%lu\",\n",info.freeram / (1024 * 1024));
    fprintf(json,"\t\"Used_Memory_(MB)\":\"%lu\",\n",(info.totalram - info.freeram) / (1024 * 1024));
    
    fprintf(json,"\t\"Used_Heap_Memory_(KB)\":\"%ld\",\n",mi.uordblks / 1024);
    
    fflush(json);
}

void log_disk_usage() 
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
    else 
    {
        fprintf(stderr, "statvfs failed: %s\n", strerror(errno));    
        exit(EXIT_FAILURE);
    }
}

void mqtt_publish_initialisation()
{
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);//  NULL = the client ID, true = client should automatically reconnect when connection is lost 
                                           //  NULL = user-defined object 
    if (!mosq) 
    {
        fprintf(stderr, "Failed To Create Mosquitto Instance: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
        fprintf(stdout, "Created Mosquitto Instance\n");

    int attempts = 0;
    for (attempts ; attempts < 5; ++attempts) 
    {

    int rc = mosquitto_connect(mosq, BROKER, 1883, 60);  //mosq = name of client, BROKER = host name, 1883 = port no (Unsecure MQTT Port), 60 = keep-alive interval in sec 
    if(rc == MOSQ_ERR_SUCCESS)
    {
        Broker_Connection_Flag = 1;
        fprintf(stdout, "Connected To MQTT Broker\n");
        break;
    }
        fprintf(stderr, "Unable To Connect To MQTT Broker: %s\nRetrying.....\n attempt no. %d\n",strerror(errno),attempts);

        sleep(1 << attempts);  
    }  
    if (attempts == 5)
    {
        fprintf(stderr, "Failed to Connect To MQTT Broker after %d attempts: %s\n",attempts,strerror(errno));
        Broker_Connection_Flag = 0;
        exit(EXIT_FAILURE);    
     }
}

void mqtt_publish()
{
    fseek(json, 0, SEEK_SET);    
    char * buffer = (char *)calloc(BUF_SIZE, sizeof(char));
    if (!buffer) 
    {
      fprintf(stderr,"Memory allocation failed: %s\n",strerror(errno));  
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

void check_disk_space_or_exit() 
{
    struct statvfs fs;

    if (statvfs("/tmp", &fs) == 0) 
    {
        unsigned long free_mb = fs.f_bfree * fs.f_frsize / (1024 * 1024);
        if (free_mb < 1) 
        {
            Memory_Flag = 1;
            fprintf(stderr, "Disk almost full! Exiting: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    } 
    else 
    {
        fprintf(stderr, "statvfs failed: %s\n", strerror(errno));    
        exit(EXIT_FAILURE);
    }
}

void signal_handler(int sig)
{
    Exit_Signal_Flag = sig;
    Keep_Running_Flag = 0; 
}


const char *get_signal_reason(int sig) 
{
    switch (sig) 
    {
        case SIGINT:  
                    return "SIGINT (Ctrl+C)";
        
        case SIGTERM: 
                    return "SIGTERM (systemd or kill)";
        
        case SIGQUIT: 
                    return "SIGQUIT (keyboard quit)";
        
        default:      
                    return "Unknown signal";
    }
}
void clean_up_resources() 
{
    if(Clean_Up_Flag)
        return;
        
    Clean_Up_Flag = 1;
        
    if (!Memory_Flag && !Json_File_Flag)
    {

    if (Exit_Signal_Flag) 
    {
        fprintf(stderr, "\nExit signal received: %s\n", get_signal_reason(Exit_Signal_Flag));
    } 
    else 
    {
        fprintf(stderr, "\nNormal program exit \n");
    }
    
    fclose(json);
    fprintf(stdout, "\"%s\" File Closed\n",DATA_FILE);
    
    if(Broker_Connection_Flag == 1)
    {
    mosquitto_disconnect(mosq);
    fprintf(stdout, "MQTT Broker Disconnected\n");
    }
    
    mosquitto_destroy(mosq);
    fprintf(stdout, "Mosquitto Instance Destroyed\n");    
    
    mosquitto_lib_cleanup();
    fprintf(stdout, "Mosquitto Lib Cleared\n");
    }
    
    fprintf(stdout, "Program Exited Successfully\n");

}
