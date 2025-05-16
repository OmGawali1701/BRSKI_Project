#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <malloc.h>

#define BUF_SIZE 1024

#define DATA_FILE "/tmp/Behavioral_Attributes_data.json"
#define TOPIC     "device/data"
#define BROKER    "localhost"

FILE *json = NULL; 

int  log_uptime();
int  log_cpu_usage();
//int  log_cpu_temp();
int  log_network_traffic();
int  log_memory_usage();
int  log_disk_usage();

void publish_cpu_data();

int main() 
{
  json = fopen("/tmp/Behavioral_Attributes_data.json","w+");
    if(!json)
    {
      perror("Could not create or open /tmp/Behavioral_Attributes_data.json");
      return -1;
    }
    
  while (1) 
    {
        fseek(json, 0, SEEK_SET);    
        ftruncate(fileno(json), 0);  
        fprintf(json, "{\n");
        
        log_uptime();
        log_cpu_usage();
    //  log_cpu_temp();
        log_memory_usage();
        log_disk_usage();
        
        fprintf(json, "}\n");
        fflush(json);
        
        publish_cpu_data();
        
        sleep(10);
    }
    fclose(json);
    return 0;
}

int log_uptime() 
{
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) 
    {
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
      perror("Could not open /proc/stat");
      return -1;
    }
    char buffer[BUF_SIZE];
    fgets(buffer, BUF_SIZE, fp);
    unsigned long long int user, nice, system, idle;
    sscanf(buffer, "cpu %llu %llu %llu %llu", &user, &nice, &system, &idle);
    fclose(fp);
    fprintf(json,"\t\"CPU_User_Time\":\"%llu\",\n",user);
    fprintf(json,"\t\"CPU_System_Time\":\"%llu\",\n",system);
    fprintf(json,"\t\"CPU_Idle_Time\":\"%llu\",\n",idle); 
    fflush(json);
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
      perror("Could not open /proc/net/dev");
      return -1;MQTT.h
    }
    char buffer[BUF_SIZE];
    for(int i = 0; i < 2; i++) 
      fgets(buffer, BUF_SIZE, fp); // Skip headers
    while (fgets(buffer, BUF_SIZE, fp))
    {
        char iface[16];
        unsigned long rx_bytes, tx_bytes;
        sscanf(buffer, "%s %lu %*s %*s %*s %*s %*s %*s %*s %lu", iface, &rx_bytes, &tx_bytes);
        iface[strlen(iface)-1] = 0; // Remove trailing ':'
        fprintf(json,"\t\"Interface_%s_RX_(Bytes)\":\"%lu\",\n",iface, rx_bytes);
        fprintf(json,"\t\"Interface_%s_TX_(Bytes)\":\"%lu\",\n",iface, tx_bytes);
        fflush(json);
    }
    fclose(fp);
}

int log_memory_usage() 
{
    struct sysinfo info;
    sysinfo(&info);
    fprintf(json,"\t\"Total_Memory_(MB)\":\"%lu\",\n",info.totalram / (1024 * 1024));
    fprintf(json,"\t\"Free_Memory_(MB)\":\"%lu\",\n",info.freeram / (1024 * 1024));
    fprintf(json,"\t\"Used_Memory_(MB)\":\"%lu\",\n",(info.totalram - info.freeram) / (1024 * 1024));
    
    struct mallinfo2 mi = mallinfo2();
    fprintf(json,"\t\"Used_Heap_Memory_(KB)\":\"%ld\",\n",mi.uordblks / 1024);
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

void publish_cpu_data() 
{
    char command[256];
    snprintf(command, sizeof(command),"mosquitto_pub -h %s -t %s -f %s",BROKER, TOPIC, DATA_FILE);
    system(command);
}


