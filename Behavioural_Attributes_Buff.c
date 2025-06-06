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
#include <stdarg.h> 

#define BUF_SIZE 1024
#define JSON_BUF_SIZE 2048

#define TOPIC     "device/data"
#define BROKER    "localhost"
 
struct mosquitto *mosq = NULL;
char JSON[JSON_BUF_SIZE];
int JSON_Index = 0;
volatile sig_atomic_t Keep_Running_Flag = 1;
volatile sig_atomic_t Memory_Flag = 0;
volatile sig_atomic_t Exit_Signal_Flag = 0;
volatile sig_atomic_t Clean_Up_Flag = 0;
volatile sig_atomic_t Broker_Connection_Flag =0;

void build_json_payload();
void device_id();
void device_static_data();
void log_uptime();
void log_cpu_usage();
void log_cpu_temp();
void log_network_traffic();
void log_memory_usage();
void log_disk_usage();

void mqtt_publish_initialisation();
void mqtt_publish();

const char *get_signal_reason(int); 
void clean_up_resources();
void signal_handler(int);

void write_to_JSON(const char * format, ...);

int main() 
{
  fprintf(stdout, "Daemon running. PID: %d\n", getpid());

  atexit(clean_up_resources);
  
  signal(SIGINT,  signal_handler);  // Ctrl+C
  signal(SIGTERM, signal_handler);  // systemd or kill
  signal(SIGQUIT, signal_handler);  // Ctrl+\
  
  mqtt_publish_initialisation();
      
  while (Keep_Running_Flag) 
    {        
        build_json_payload();       
      
        mqtt_publish();
        
        sleep(10);
    }
        clean_up_resources();
        return 0;
}

void build_json_payload()
{
        device_id();
        device_static_data();
        log_uptime();
        log_cpu_temp();
        log_cpu_usage();
        log_network_traffic();
        log_memory_usage();
        log_disk_usage();
        
        write_to_JSON("}\n");
        
        JSON[JSON_Index] = '\0';
}

void device_id()
{
    char device_id[128] = {0};
    FILE *fp = fopen("/etc/machine-id", "r");
    if(!fp)
    {
      fprintf(stderr,"Could not open /etc/machine-id: %s\n",strerror(errno));
      fprintf(stdout,"Skipping Device ID Creation\n");
    }
    
      fgets(device_id, sizeof(device_id), fp);
      device_id[strcspn(device_id, "\n")] = '\0'; 
      fclose(fp);
      write_to_JSON("{\n\t\"Device_ID\":\"%s\",\n",device_id);
}

void device_static_data()
{
    char os[128] = "Unknown";
    char hostname[128] = "Unknown";
    char kernel[256] = "Unknown";
    char cpu_model[256] = "Unknown";
    int package_count = 0;
    int core_count = 0;
    char line[256];
    
    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) 
    {
        fprintf(stderr, "Could not open /etc/os-release: %s\n", strerror(errno));
        fprintf(stdout, "Skipping OS Name Collection\n");
    } 
    else 
    {
        while (fgets(os, sizeof(os), fp)) 
        {
            if (strncmp(os, "PRETTY_NAME=", 12) == 0) 
            {
                char * val = strchr(os, '=');
                
                if (val) 
                {
                val++; 
                if (*val == '"')
                    val++; 
                val[strcspn(val, "\"\n")] = '\0'; 
                memmove(os, val, strlen(val) + 1); 
            }
                break;
            }
        }
        fclose(fp);
    }

    fp = fopen("/etc/hostname", "r");
    if(!fp)
    {
        fprintf(stderr, "Could not open /etc/hostname: %s\n", strerror(errno));
        fprintf(stdout, "Skipping Hostname Collection\n");
    }
    else 
    {
        fgets(hostname, sizeof(hostname), fp);
        hostname[strcspn(hostname, "\n")] = '\0';
        fclose(fp);
    }

    fp = fopen("/proc/version", "r");
    
    if(!fp)
    {
        fprintf(stderr, "Could not open /proc/version: %s\n", strerror(errno));
        fprintf(stdout, "Skipping Kernel Information Collection\n");
    }
    else 
    {        
        if(fgets(kernel, sizeof(kernel), fp))
        {
        char val[128]= {0};
        if(sscanf(kernel,"%*s %*s %127s",val) == 1)
            {
                strncpy(kernel,val,sizeof(val));
                kernel[sizeof(kernel)-1]= '\0';
            }
        }
        fclose(fp);
    }

    fp = fopen("/var/lib/dpkg/status", "r");
    
    if(!fp)
    {
        fprintf(stderr, "Could not open /var/lib/dpkg/status: %s\n", strerror(errno));
        fprintf(stdout, "Skipping Packages Information Collection\n");
    }    
    else 
    {
        while (fgets(line, sizeof(line), fp)) 
        {
            if (strncmp(line, "Package:", 8) == 0)
                package_count++;
        }
        fclose(fp);
    }

    fp = fopen("/proc/cpuinfo", "r");
    if(!fp)
    {
        fprintf(stderr, "Could not open /proc/cpuinfo: %s\n", strerror(errno));
        fprintf(stdout, "Skipping CPU Information Collection\n");
    }    
    
    else 
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, "model name", 10) == 0) 
            {
                char *val = strchr(line, ':');
                if (val) 
                {
                    val += 2;
                    val[strcspn(val, "\n")] = '\0';
                    strncpy(cpu_model, val, sizeof(cpu_model));
                    break;
                }
            }
        }
        fclose(fp);
    }

    fp = fopen("/proc/stat", "r");
    if(!fp)
    {
        fprintf(stderr, "Could not open /proc/stat: %s\n", strerror(errno));
        fprintf(stdout, "Skipping CPU Core Count Collection\n");
    }
    else
    {
        while (fgets(line, sizeof(line), fp)) 
        {
            if (strncmp(line, "cpu", 3) == 0 && (line[3] >= '0' && line[3] <= '9'))
                core_count++;
        }
        fclose(fp);
    }
    write_to_JSON(
                  "\n\t\"Device_Static_Data\":{"
                  "\n\t\t\t\"OS_Name\":\"%s\","
                  "\n\t\t\t\"Hostname\":\"%s\","
                  "\n\t\t\t\"CPU_Model\":\"%s\","
                  "\n\t\t\t\"CPU_Core_Count\":\"%d\","                  
                  "\n\t\t\t\"Kernel\":\"%s\","
                  "\n\t\t\t\"Installed_Package\":\"%d\""                     
                  "\n\t\t\t},\n",os, hostname, cpu_model, core_count, kernel, package_count);      
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
 
    write_to_JSON("\n\t\"Up_Time\":\"%lf\",\n",uptime);

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
    
    write_to_JSON(
                  "\n\t\"CPU_Usage\":{"
                  "\n\t\t\t\"CPU_User_Time\":\"%llu\","
                  "\n\t\t\t\"CPU_System_Time\":\"%llu\","
                  "\n\t\t\t\"CPU_Idle_Time\":\"%llu\""
                  "\n\t\t\t},\n", user, system, idle);

    free(buffer);
    }
    }
}

void log_cpu_temp() 
{ 
    char path[64], type[64];
    int temp, zone = 0;

    while (1) 
    {
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/type", zone);
        FILE *fp = fopen(path, "r");
        if (!fp) 
        {
          if(zone == 0)
          {
            fprintf(stderr, "Temperature sensor not found. Skipping Temp read : %s\n",strerror(errno));   
            break;
          }
          else
          {
              if(JSON[JSON_Index-1] == ',')
                  JSON_Index--;
              write_to_JSON("\n\t\t\t},\n");
            break;
          }
        }  

        if (fgets(type, sizeof(type), fp))
        {
            type[strcspn(type, "\n")] = '\0'; 
        }
        fclose(fp);

        if (strstr(type, "x86_pkg_temp") || strstr(type, "cpu") || strstr(type, "core")) 
        {
            snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", zone);
            fp = fopen(path, "r");
            if (fp && fscanf(fp, "%d", &temp) == 1) 
            {
                if(zone == 0)
                    write_to_JSON("\n\t\"CPU_Core_Temperature\":{");
                    
                write_to_JSON("\n\t\t\t\"CPU_Core%d_Temperature_(°C)\":\"%.2f\",", zone, temp / 1000.0);
                fclose(fp);
            } 
            else 
            {
                if (fp) 
                fclose(fp);
            }
        }
        zone++;
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
     write_to_JSON("\n\t\"Network_Traffic\":{\n");
    for(int i = 0; i < 2; i++) 
      fgets(buffer, 512, fp); // Skip headers
    while (fgets(buffer, 512, fp))
    {
        char iface[16];
        unsigned long rx_bytes, tx_bytes, rx_packets, tx_packets;
        if (sscanf(buffer, "%15s %lu %lu %*s %*s %*s %*s %*s %*s %lu %lu", iface, &rx_bytes, &rx_packets, &tx_bytes, &tx_packets) == 5)
        {
            iface[strcspn(iface, ":")] = '\0'; // Safe colon removal
            write_to_JSON(
                         "\n\t\t\t\"%s\":{"
                         "\n\t\t\t\t\"Interface_RX_(Bytes)\":\"%lu\","
                         "\n\t\t\t\t\"Interface_TX_(Bytes)\":\"%lu\""
                         "\n\t\t\t\t\"Interface_RX_(Packets)\":\"%lu\""
                         "\n\t\t\t\t\"Interface_TX_(Packets)\":\"%lu\""
                         "\n\t\t\t\t},\n", iface, rx_bytes, tx_bytes, rx_packets, tx_packets );
        }
    }
    free(buffer);
    }
    fclose(fp);
    }
    if (JSON_Index >= 2 && JSON[JSON_Index - 2] == ',' && JSON[JSON_Index - 1] == '\n')
    {
        JSON_Index -= 2;
    }

    write_to_JSON("\n\t},\n");
}

void log_memory_usage() 
{ 
    struct sysinfo info;
    sysinfo(&info);
    struct mallinfo2 mi = mallinfo2();
    
    write_to_JSON(
                  "\n\t\"Memory_Usage\":{"
                  "\n\t\t\t\"Total_Memory_(MB)\":\"%lu\","
                  "\n\t\t\t\"Free_Memory_(MB)\":\"%lu\","
                  "\n\t\t\t\"Used_Memory_(MB)\":\"%lu\","
                  "\n\t\t\t\"Used_Heap_Memory_(KB)\":\"%ld\""
                  "\n\t\t\t},\n", info.totalram / (1024 * 1024),info.freeram / (1024 * 1024), (info.totalram - info.freeram) / (1024 * 1024), mi.uordblks / 1024);
}

void log_disk_usage() 
{
    struct statvfs fs;
    if (statvfs("/", &fs) == 0) 
    {
        unsigned long total = fs.f_blocks * fs.f_frsize / (1024 * 1024);
        unsigned long free = fs.f_bfree * fs.f_frsize / (1024 * 1024);
        unsigned long used = total - free;
        
        write_to_JSON(
                      "\n\t\"Disk_Usage\":{"
                      "\n\t\t\t\"Disk_Total_(MB)\":\"%lu\","
                      "\n\t\t\t\"Disk_used_(MB)\":\"%lu\","
                      "\n\t\t\t\"Disk_free_(MB)\":\"%lu\""
                      "\n\t\t\t}\n", total,used,free);
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
        fprintf(stderr, "Unable To Connect To MQTT Broker: %s\nRetrying.....\n attempt no. %d\n", mosquitto_strerror(rc),attempts);

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
    
    int rc = mosquitto_publish(mosq, NULL, TOPIC, strlen(JSON), JSON, 0, false);

    if (rc != MOSQ_ERR_SUCCESS) 
    {
      fprintf(stderr, "Failed to publish: %s\n", mosquitto_strerror(rc));
    }
    JSON_Index = 0;
    
    fprintf(stderr, "Data Published\n");

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
        
    if (!Memory_Flag)
    {

    if (Exit_Signal_Flag) 
    {
        fprintf(stderr, "\nExit signal received: %s\n", get_signal_reason(Exit_Signal_Flag));
    } 
    else 
    {
        fprintf(stderr, "\nNormal program exit \n");
    }
    
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

void write_to_JSON(const char * format, ...)
{
    va_list args;
    va_start(args, format);
    JSON_Index += vsnprintf(JSON + JSON_Index,JSON_BUF_SIZE - JSON_Index,format, args);
    va_end(args);
}
