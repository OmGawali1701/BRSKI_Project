#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <malloc.h>
#include <signal.h>

#include <mosquitto.h>


#define BUF_SIZE 1024
#define JSON_BUF_SIZE 4096

#define MAX_EVENTS 5

#define MAX_TOP_PROCS 5

typedef struct {
    pid_t pid;
    char comm[256];
    double cpu_usage;
} ProcInfo;

#define TOPIC     "device/data"
#define BROKER    "10.182.3.33"

#define CA_CERT_PATH "/etc/ssl/behavioural_agent/ca.crt"
#define CLIENT_CERT_PATH "/etc/ssl/behavioural_agent/client.crt"
#define CLIENT_PVT_KEY_PATH "/etc/ssl/behavioural_agent/client.key"

#define MAC_PATH_TEMPLATE "/sys/class/net/%s/address"
#define MAC_ADDR_LEN 32

struct mosquitto *mosq = NULL;
char JSON[JSON_BUF_SIZE];
int JSON_Index = 0;
volatile sig_atomic_t Keep_Running_Flag = 1;
volatile sig_atomic_t Memory_Flag = 0;
volatile sig_atomic_t Exit_Signal_Flag = 0;
volatile sig_atomic_t Clean_Up_Flag = 0;
volatile sig_atomic_t Broker_Connection_Flag =0;

void time_stamp();
void build_json_payload();
void device_id();
void device_static_data();
void log_uptime();
void log_cpu_usage();
void log_cpu_temp();
void log_network_traffic();
int get_ip_address(const char *, char *, size_t) ;
int get_mac_address(const char *, char *, size_t);
void log_memory_usage();
void log_disk_usage(); 
void log_top_cpu_processes();
void log_current_users();
void log_failed_logins();
void log_reboots_shutdowns();
int compare_cpu_usage(const void *, const void *);
int filter_numeric_dirs(const struct dirent *);
double read_cpu_time(pid_t );


void mqtt_publish_initialisation();
void mqtt_publish();

const char *get_signal_reason(int); 
void clean_up_resources();
void signal_handler(int);

void log_with_timestamp(FILE *, const char *, ...);

void write_to_JSON(const char * format, ...);

int main() 
{
  setvbuf(stdout, NULL, _IONBF, 0);  
  setvbuf(stderr, NULL, _IONBF, 0);
  
  log_with_timestamp(stdout, "Daemon running. PID: %d\n", getpid());

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
        write_to_JSON("{\n");
        
        time_stamp();
        device_id();
        device_static_data();
        log_uptime();
        log_cpu_temp();
        log_cpu_usage();
        log_network_traffic();
        log_memory_usage();
        log_disk_usage();
        log_top_cpu_processes();
        log_current_users();
        log_reboots_shutdowns();
        log_failed_logins();
        
        write_to_JSON("}\n");
        
        JSON[JSON_Index] = '\0';
}

void time_stamp()
{
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    write_to_JSON("\t\"Timestamp\":\"%s\",\n", time_str);
}

void device_id()
{
    char device_id[128] = {0};
    FILE *fp = fopen("/etc/machine-id", "r");
    if(!fp)
    {
      log_with_timestamp(stderr,"Could not open /etc/machine-id: %s\n",strerror(errno));
      log_with_timestamp(stdout,"Skipping Device ID Creation\n");
    }
    else
    {
      fgets(device_id, sizeof(device_id), fp);
      device_id[strcspn(device_id, "\n")] = '\0'; 
      fclose(fp);
      write_to_JSON("\t\"Device_ID\":\"%s\",\n",device_id);
    }
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
        log_with_timestamp(stderr, "Could not open /etc/os-release: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping OS Name Collection\n");
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
        log_with_timestamp(stderr, "Could not open /etc/hostname: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping Hostname Collection\n");
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
        log_with_timestamp(stderr, "Could not open /proc/version: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping Kernel Information Collection\n");
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
        log_with_timestamp(stderr, "Could not open /var/lib/dpkg/status: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping Packages Information Collection\n");
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
        log_with_timestamp(stderr, "Could not open /proc/cpuinfo: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping CPU Information Collection\n");
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
        log_with_timestamp(stderr, "Could not open /proc/stat: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping CPU Core Count Collection\n");
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
      log_with_timestamp(stderr,"Could not open /proc/uptime: %s\n",strerror(errno));
      log_with_timestamp(stdout,"Skipping Uptime read\n");
    }
    else
    {
    double uptime;
    fscanf(fp, "%lf", &uptime);
 
    write_to_JSON("\n\t\"Up_Time\":\"%lf\",\n",uptime);

    fclose(fp);
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
            log_with_timestamp(stderr, "Temperature sensor not found. Skipping Temp read : %s\n",strerror(errno));   
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

        if (strstr(type, "x86_pkg_temp") || strstr(type, "cpu") || strstr(type, "core") || strstr(type, "imx_thermal_zone")) 
        {
            snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", zone);
            fp = fopen(path, "r");
            if (fp && fscanf(fp, "%d", &temp) == 1) 
            {
                if(zone == 0)
                    write_to_JSON("\n\t\"CPU_Core_Temperature\":{");
                    
                write_to_JSON("\n\t\t\t\"CPU_Core%d_Temperature_(C)\":\"%.2f\",", zone, temp / 1000.0);
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



void log_cpu_usage() 
{
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) 
    {
      log_with_timestamp(stderr,"Could not open /proc/stat: %s\n",strerror(errno));
      log_with_timestamp(stdout,"Skipping CPU Usage read\n");
    }
    else
    {
    char * buffer = (char *)calloc(BUF_SIZE,sizeof(char));
    if (!buffer)
    {
        log_with_timestamp(stderr,"Memory allocation failed: %s\n",strerror(errno));  
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

void log_network_traffic() 
{
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) 
    {
      log_with_timestamp(stderr, "Could not open /proc/net/dev: %s\n",strerror(errno));
      log_with_timestamp(stdout,"Skipping Network Traffic read\n");
    }
    else
    {
    char * buffer = (char *)calloc(512,sizeof(char));
    if (!buffer)
    {
        log_with_timestamp(stderr, "Memory Allocation Failed: %s\n",strerror(errno));
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
            
            char ip[INET_ADDRSTRLEN] = "N/A";
            char mac[MAC_ADDR_LEN] = "N/A";

            get_ip_address(iface, ip, sizeof(ip));
            get_mac_address(iface, mac, sizeof(mac));
            
            write_to_JSON(
                         "\n\t\t\t\"%s\":{"
                         "\n\t\t\t\t\"IP_Address\": \"%s\","
                         "\n\t\t\t\t\"MAC_Address\": \"%s\","
                         "\n\t\t\t\t\"Interface_RX_(Bytes)\":\"%lu\","
                         "\n\t\t\t\t\"Interface_TX_(Bytes)\":\"%lu\","
                         "\n\t\t\t\t\"Interface_RX_(Packets)\":\"%lu\","
                         "\n\t\t\t\t\"Interface_TX_(Packets)\":\"%lu\""
                         "\n\t\t\t\t},\n", iface, ip, mac, rx_bytes, tx_bytes, rx_packets, tx_packets );
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

    write_to_JSON("\n\t\t\t},\n");
}

int get_ip_address(const char *iface, char *ip_buffer, size_t buflen) 
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;  // interface may not have IP
    }

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ip_buffer, inet_ntoa(ipaddr->sin_addr), buflen);
    close(fd);
    return 0;
}

int get_mac_address(const char *iface, char *mac_buffer, size_t buflen) 
{
    char path[128];
    snprintf(path, sizeof(path), MAC_PATH_TEMPLATE, iface);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    if (!fgets(mac_buffer, buflen, fp)) {
        fclose(fp);
        return -1;
    }
    mac_buffer[strcspn(mac_buffer, "\n")] = 0;
    fclose(fp);
    return 0;
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


void log_top_cpu_processes() 
{
    struct dirent **namelist;
    int n = scandir("/proc", &namelist, filter_numeric_dirs, NULL);
    if (n < 0) 
    {
        log_with_timestamp(stderr, "scandir failed: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping the TOP CPU processes collection.\n");
        return;
    }

    ProcInfo *procs = calloc(n, sizeof(ProcInfo));
    if (!procs) 
    {
        log_with_timestamp(stderr, "Memory allocation failed\n");
        for (int i = 0; i < n; i++) free(namelist[i]);
        free(namelist);
        return;
    }

    int count = 0;
    for (int i = 0; i < n && count < n; i++) 
    {
        pid_t pid = atoi(namelist[i]->d_name);
        double cpu = read_cpu_time(pid);
        if (cpu < 0) 
        {
            free(namelist[i]);
            continue;
        }

        procs[count].pid = pid;
        procs[count].cpu_usage = cpu;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *fp = fopen(path, "r");
        if (fp) 
        {
            fgets(procs[count].comm, sizeof(procs[count].comm), fp);
            strtok(procs[count].comm, "\n");
            fclose(fp);
        } else 
        {
            strncpy(procs[count].comm, "unknown", sizeof(procs[count].comm));
        }

        count++;
        free(namelist[i]);
    }
    free(namelist);

    qsort(procs, count, sizeof(ProcInfo), compare_cpu_usage);

    if (count > MAX_TOP_PROCS)
        count = MAX_TOP_PROCS;

    write_to_JSON("\n\t\"Top_CPU_Processes\": [\n");
    for (int i = 0; i < count; i++) 
    {
        write_to_JSON(
            "\t\t\t{"
            "\n\t\t\t\t\"PID\": \"%d\","
            "\n\t\t\t\t\"Command\": \"%s\","
            "\n\t\t\t\t\"CPU_Usage_(sec)\": \"%.2f\""
            "\n\t\t\t}%s\n",
            procs[i].pid, procs[i].comm, procs[i].cpu_usage,
            (i < count - 1) ? "," : "");
    }
    write_to_JSON("\t\t\t],\n");

    free(procs);
}

int filter_numeric_dirs(const struct dirent *entry) 
{
    if (entry->d_type != DT_DIR)
        return 0;

    const char *name = entry->d_name;
    while (*name) 
    {
        if (!isdigit(*name)) return 0;
        name++;
    }
    return 1;
}

double read_cpu_time(pid_t pid) 
{
    char path[256], comm[256], state;
    unsigned long utime, stime;
    double total_time = 0;
    long clk_tck = sysconf(_SC_CLK_TCK);


    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) return -1;

    fscanf(fp, "%*d (%255[^)]) %c", comm, &state);  
    for (int i = 0; i < 11; i++) fscanf(fp, "%*s"); 
    fscanf(fp, "%lu %lu", &utime, &stime);
    fclose(fp);
    total_time = (utime + stime) / (double)clk_tck;
    return total_time;
}

int compare_cpu_usage(const void *a, const void *b) 
{
    ProcInfo *p1 = (ProcInfo *)a;
    ProcInfo *p2 = (ProcInfo *)b;
    if (p2->cpu_usage > p1->cpu_usage) return 1;
    if (p2->cpu_usage < p1->cpu_usage) return -1;
    return 0;
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
                      "\n\t\t\t},\n", total,used,free);
    }
    else 
    {
        log_with_timestamp(stderr, "statvfs failed: %s\n", strerror(errno));    
        exit(EXIT_FAILURE);
    }
}

void log_current_users()
{
    struct utmp entry;
    FILE *fp = fopen("/var/run/utmp", "rb");  // or "/run/utmp" on some systems
    if (!fp)
    {
        log_with_timestamp(stderr, "Could not open /var/run/utmp: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping the Current logged user collection.\n");
        write_to_JSON("\n\t\"Current_Users\":[]\n");
        return;
    }

    write_to_JSON("\n\t\"Current_Users\":[\n");

    int first = 1;
    while (fread(&entry, sizeof(struct utmp), 1, fp) == 1)
    {
        if (entry.ut_type == USER_PROCESS)
        {
            time_t t = entry.ut_time;
            char time_buf[64];
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));

            write_to_JSON(
                          "%s\t\t\t{"
                          "\n\t\t\t\t\"User\":\"%s\","
                          "\n\t\t\t\t\"Line\":\"%s\","
                          "\n\t\t\t\t\"Host\":\"%s\","
                          "\n\t\t\t\t\"Login_Time\":\"%s\""
                          "\n\t\t\t}",(first ? "" : ",\n"),entry.ut_user, entry.ut_line, entry.ut_host, time_buf
                        );
           first = 0;
        }
    }

    write_to_JSON("\n\t\t\t],\n");
    fclose(fp);
}


void log_reboots_shutdowns() 
{
    FILE *fp = fopen("/var/log/wtmp", "rb");
    if (!fp) 
    {
        log_with_timestamp(stderr, "Could not open /var/log/wtmp: %s\n", strerror(errno));
        log_with_timestamp(stdout, "Skipping the Reboot History collection.\n");
        write_to_JSON("\n\t\"Last_Reboots_Shutdowns\":\"Failed to open wtmp log\",\n");
        return;
    }

    struct utmp entry;
    struct utmp last_reboots[MAX_EVENTS];
    int count = 0;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    long pos = file_size - sizeof(struct utmp);

    while (pos >= 0 && count < MAX_EVENTS) 
    {
        fseek(fp, pos, SEEK_SET);
        fread(&entry, sizeof(struct utmp), 1, fp);

        if (entry.ut_type == BOOT_TIME) 
        {
            last_reboots[count++] = entry;
        }

        pos -= sizeof(struct utmp);
    }

    fclose(fp);

    write_to_JSON("\n\t\"Reboots_Shutdowns\":[");

    for (int i = count - 1; i >= 0; i--) {
        char *type = (last_reboots[i].ut_type == BOOT_TIME) ? "Reboot" : "Shutdown";
        time_t t = last_reboots[i].ut_time;
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));

        write_to_JSON(
                      "\n\t\t\t\t{"
                      "\n\t\t\t\t\"Type\":\"%s\","
                      "\n\t\t\t\t\"Time\":\"%s\""
                      "\n\t\t\t\t}%s\n", type, time_buf, (i > 0 ? "," : "")
                      );
    }
    write_to_JSON("\t\t\t],\n");
}

void log_failed_logins() 
{
    const char *paths[] = {"/var/log/btmp", "/var/log/btmp.1"};
    struct utmp entry;
    struct utmp last_fails[MAX_EVENTS];
    int count = 0;
    
    for (int p = 0; p < 2 && count < MAX_EVENTS; ++p)
    {
        FILE *fp = fopen(paths[p], "rb");
        if (!fp)
        {
            log_with_timestamp(stderr, "Could not open %s: %s\n", paths[p], strerror(errno));
            continue;
        }

        while (fread(&entry, sizeof(struct utmp), 1, fp) == 1)
        {
            if ( entry.ut_type == LOGIN_PROCESS && (strlen(entry.ut_host) > 0) && strcmp(entry.ut_host, ":0") != 0)
            {
                if (count < MAX_EVENTS)
                    last_fails[count++] = entry;
                else
                    break;
            }
        }

        fclose(fp);
    }
    write_to_JSON("\n\t\"Failed_Login_Attempts\":[\n");

    for (int i = 0; i < count; i++) 
    {
    time_t t = 0;
    #if defined(__linux__)
        t = last_fails[i].ut_tv.tv_sec;
    #else
        t = last_fails[i].ut_time;
    #endif
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));

        write_to_JSON(
                      "\n\t\t\t\t{"
                      "\n\t\t\t\t\"User\":\"%s\","
                      "\n\t\t\t\t\"Line\":\"%s\","
                      "\n\t\t\t\t\"Host\":\"%s\","
                      "\n\t\t\t\t\"Time\":\"%s\""
                      "\n\t\t\t\t}%s", last_fails[i].ut_user, last_fails[i].ut_line, last_fails[i].ut_host, time_buf, (i < count - 1 ? "," : "")
                      );
    }

    write_to_JSON("\n\t\t\t]\n");
}

void mqtt_publish_initialisation()
{
    const char *online_payload = "{\"status\": \"online\"}";
    const char *will_payload = "{\"status\": \"disconnected_unexpectedly\"}";

    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);//  NULL = the client ID, true = client should automatically reconnect when connection is lost 
                                           //  NULL = user-defined object 
    if (!mosq) 
    {
        log_with_timestamp(stderr, "Failed To Create Mosquitto Instance: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
        log_with_timestamp(stdout, "Created Mosquitto Instance\n");
    
    int lwt_rc = mosquitto_will_set(mosq, TOPIC, strlen(will_payload),
                                    will_payload, 1, false);
    if (lwt_rc != MOSQ_ERR_SUCCESS) 
    {
        log_with_timestamp(stderr, "Failed to set Last Will: %s\n", mosquitto_strerror(lwt_rc));
        exit(EXIT_FAILURE);
    }
    log_with_timestamp(stdout, "LWT Set Successfully\n");
    
     int tls_rc = mosquitto_tls_set(mosq,CA_CERT_PATH, NULL,CLIENT_CERT_PATH,CLIENT_PVT_KEY_PATH,NULL);

    if (tls_rc != MOSQ_ERR_SUCCESS) 
    {
        log_with_timestamp(stderr, "Failed to set TLS options: %s\n", mosquitto_strerror(tls_rc));
        exit(EXIT_FAILURE);
    }
        log_with_timestamp(stdout, "Mosquitto TLS Setup Done\n");
    mosquitto_tls_insecure_set(mosq, false);
    
    int attempts = 0;
    for (attempts ; attempts < 5; ++attempts) 
    {

    int rc = mosquitto_connect(mosq, BROKER, 8883, 60);  //mosq = name of client, BROKER = host name, 1883 = port no (Unsecure MQTT Port), 60 = keep-alive interval in sec 
    if(rc == MOSQ_ERR_SUCCESS)
    {
        Broker_Connection_Flag = 1;
        log_with_timestamp(stdout, "Connected To MQTT Broker\n");
        
        mosquitto_publish(mosq, NULL, TOPIC, strlen(online_payload),
                  online_payload, 1, false);
        mosquitto_loop_start(mosq);

        break;
    }
        log_with_timestamp(stderr, "Unable To Connect To MQTT Broker: %s\nRetrying.....\n attempt no. %d\n", mosquitto_strerror(rc),attempts);

        sleep(1 << attempts);  
    }  
    if (attempts == 5)
    {
        log_with_timestamp(stderr, "Failed to Connect To MQTT Broker after %d attempts: %s\n",attempts,strerror(errno));
        Broker_Connection_Flag = 0;
        exit(EXIT_FAILURE);    
     }
}

void mqtt_publish()
{
    
    int rc = mosquitto_publish(mosq, NULL, TOPIC, strlen(JSON), JSON, 0, false);

    if (rc != MOSQ_ERR_SUCCESS) 
    {
      log_with_timestamp(stderr, "Failed to publish: %s\n", mosquitto_strerror(rc));
    }
    else
    {
    log_with_timestamp(stdout, "Data Published\n");
    }
    JSON_Index = 0;
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
            log_with_timestamp(stderr, "Disk almost full! Exiting: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    } 
    else 
    {
        log_with_timestamp(stderr, "statvfs failed: %s\n", strerror(errno));    
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
        log_with_timestamp(stderr, "\nExit signal received: %s\n", get_signal_reason(Exit_Signal_Flag));
    } 
    else 
    {
        log_with_timestamp(stderr, "\nNormal program exit \n");
    }
    
    if(Broker_Connection_Flag == 1)
    {
    const char *offline_payload = "{\"status\": \"offline\"}";
    mosquitto_publish(mosq, NULL, TOPIC, strlen(offline_payload), offline_payload, 1, false);
    sleep(1);  // Give time to send
    mosquitto_disconnect(mosq);
    mosquitto_disconnect(mosq);
    
    log_with_timestamp(stdout, "MQTT Broker Disconnected\n");
    
    }
    
    mosquitto_destroy(mosq);
    log_with_timestamp(stdout, "Mosquitto Instance Destroyed\n");    
    
    mosquitto_lib_cleanup();
    log_with_timestamp(stdout, "Mosquitto Lib Cleared\n");
    }
    
    log_with_timestamp(stdout, "Program Exited Successfully\n");
}

void log_with_timestamp(FILE *stream, const char *format, ...)
{
    char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "[%Y-%m-%d %H:%M:%S]", tm_info);

    fprintf(stream, "%s ", time_buf);  // Prefix timestamp

    va_list args;
    va_start(args, format);
    vfprintf(stream, format, args);    // Original message
    va_end(args);
}


void write_to_JSON(const char * format, ...)
{
    va_list args;
    va_start(args, format);
    JSON_Index += vsnprintf(JSON + JSON_Index,JSON_BUF_SIZE - JSON_Index,format, args);
    va_end(args);
}
