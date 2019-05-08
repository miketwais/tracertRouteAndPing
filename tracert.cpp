#pragma warning(disable:4996)
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <cstdlib>
#include <IPHlpApi.h>
#include <process.h>
#include "tracert.h"
#include <iostream>  
#include <sstream>    //使用stringstream需要引入这个头文件  
#include <string>
using  std::string;
using  std::wstring;
using namespace std;
//增加静态链接库ws2_32.lib
#pragma comment(lib,"ws2_32.lib")
//声明3个函数类型的指针
typedef HANDLE(WINAPI *lpIcmpCreateFile)(VOID);
typedef BOOL(WINAPI *lpIcmpCloseHandle)(HANDLE  IcmpHandle);
typedef DWORD(WINAPI *lpIcmpSendEcho)(
	HANDLE                   IcmpHandle,
	IPAddr                   DestinationAddress,
	LPVOID                   RequestData,
	WORD                     RequestSize,
	PIP_OPTION_INFORMATION   RequestOptions,
	LPVOID                   ReplyBuffer,
	DWORD                    ReplySize,
	DWORD                    Timeout
	);
bool tracing;
struct trace_thread { //tracert线程结构体
	int			address;
	int			ttl;
	int			index;
};

//定义3个函数指针
lpIcmpCreateFile IcmpCreateFile;
lpIcmpCloseHandle IcmpCloseHandle;
lpIcmpSendEcho IcmpSendEcho;
//打开ICMP句柄
HANDLE hIcmp;
//设置IP报头的TTL值
//IP_OPTION_INFORMATION IpOption;
//设置要发送的数据
char SendData[32];
//设置接收缓冲区
char ReplyBuffer[sizeof(ICMP_ECHO_REPLY)+32];
PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
BOOL bLoop = TRUE;
void TraceThread(void *p);
void NodeThread(void *p);
unsigned long ip;
string a[30][4];//二维数组用来存储结果
HANDLE hMutex = NULL; //互斥量  
//long转string
string ltos(long l)
{
	char* ss = "";
	string res;
	sprintf(ss, "%s", l);
	res = ss;
	return res;

}
string num2str(ULONG i)
{
	stringstream ss;
	ss << i;
	return ss.str();
}
string int2str(int i)
{
	stringstream ss;
	ss << i;
	return ss.str();
}

//char*转string 
string char2str(char* i)
{
	string res;
	res = i;
	return res;
}
//根据域名获得ip
string GetIP(LPCSTR pszName)
{
	HOSTENT* pHE = ::gethostbyname(pszName);
	if (NULL == pHE) return "";
	return inet_ntoa(*((in_addr*)pHE->h_addr_list[0]));
}
int main(int argc, char* argv[]){
	//在tracertTest.exe后面直接接收四个参数：char host,bool IsPing, int -l,int -n例如：www.baidu.com true 10 10
	//if (argc != 4){//为了限制参数个数为4
	//	printf("Params: char host,bool IsPing, int -l,int -n");
	//	exit(-1);
	//}
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0){
		printf("WSAStartup failed.\n");
		exit(-1);
	}
	//for test
	//argv[1] = "www.baidu.com";
	/*argv[1] = "www.baidu.com";
	argv[2] = "false";
	argv[3] = "5";
	argv[4] = "5";*/
	//test
	//char line[100];
	//sprintf(line, "echo tracertTest %s %s %s %s\n\n", char2str(argv[1]).c_str(), char2str(argv[2]).c_str(), char2str(argv[3]).c_str(), char2str(argv[4]).c_str());
	//system(line);
	//system("echo.");//换行
	
	char temp[100];
	//char *buf;
	//argv[1] = "10.20.21.244";
	//转换IP地址到整数
	ip = inet_addr(argv[1]);//将一个点分十进制的IP转换成一个长整数型数（u_long类型）
	if (ip == INADDR_NONE){//用来判断输入的是不是ip地址,inet_addr失败时返回INADDR_NONE
		//用户可能输入的是域名
		hostent* pHost = gethostbyname(argv[1]);//返回对应于给定主机名的包含主机名字和地址信息的hostent结构的指针
		//如果域名无法解析
		if (pHost == NULL){
			printf("Invalid IP or domain name: %s\n", argv[1]);
			exit(-1);
		}
		//取域名的第一个IP地址
		ip = *(unsigned long*)pHost->h_addr_list[0];
		sprintf(temp, "echo traceroute to %s(%s):\n\n", char2str(argv[1]).c_str(), char2str(inet_ntoa(*(in_addr*)&ip)).c_str());
	}
	else{
		sprintf(temp, "echo traceroute to %s:\n\n", char2str(argv[1]).c_str());
	}
	system(temp);
	system("echo.");//换行
	//载入ICMP.DLL动态库
	HMODULE hIcmpDll = ::LoadLibraryEx(TEXT("icmp.dll"), NULL, 0);
	//HMODULE hIcmpDll = LoadLibrary("icmp.dll");
	if (hIcmpDll == NULL){
		printf("fail to load icmp.dll\n");
		exit(-1);
	}
	
	//从ICMP.DLL中获取所需的函数入口地址
	IcmpCreateFile = (lpIcmpCreateFile)GetProcAddress(hIcmpDll, "IcmpCreateFile");
	IcmpCloseHandle = (lpIcmpCloseHandle)GetProcAddress(hIcmpDll, "IcmpCloseHandle");
	IcmpSendEcho = (lpIcmpSendEcho)GetProcAddress(hIcmpDll, "IcmpSendEcho");
	
	if ((hIcmp = IcmpCreateFile()) == INVALID_HANDLE_VALUE){
		printf("\tUnable to open ICMP file.\n");
		exit(-1);
	}
	

	memset(SendData, '0', sizeof(SendData));
	//void *memset(void *s,int c,size_t n)
	//总的作用：将已开辟内存空间 s 的首 n 个字节的值设为值 c。
	
	
	int iMaxHop = 30;
	//typedef void **HANDLE;
	//多线程实现
	HANDLE hThreads[90];
	hMutex = CreateMutex(NULL, FALSE, "Test"); //创建互斥量
	// one thread per TTL value
	for (int i = 0; i < iMaxHop; i++) {
		for (int j = 0; j < 3; j++){
			trace_thread *current = new trace_thread;
			current->address = inet_addr(inet_ntoa(*(in_addr*)&ip));
			current->ttl = i + 1;
			current->index = j;
			hThreads[i] = (HANDLE)_beginthread(NodeThread, 0, current);//无论什么服务，都启动30个Tracert线程（最多30个跃点），当然每个线程的ttl都加1
			Sleep(20);
		}
	}
	//Sleep(3000);//保险
	//CloseHandle(hThreads);
	WaitForMultipleObjects(90, hThreads, TRUE, INFINITE);//等待所有线程执行结束后,放这里是错误的使用！！！
	IcmpCloseHandle(hIcmp);
	FreeLibrary(hIcmpDll);
	WSACleanup();

	//将数组中重复的数据清除掉
	int completIndex;
	for (int k = 0; k < 30; k++){
		//或strcmp(aa1.c_str(),bb2.c_str())==0表示相等。
		if (a[k][3].compare(inet_ntoa(*(in_addr*)&(ip))) == 0){
			/*if (k == 0){
				completIndex = 0;
			}
			else{*/
				completIndex = k;//在k节点处complete tracert!
			//}
			break;
		}
		else{
			completIndex = 29;//针对后面完全不通的情况
		}
	}
	completIndex++;//自增1
	char temp0[40],temp1[40], temp2[100];
	for (int i = 0; i < completIndex; i++){     //将数组中的元素全部输出
		sprintf(temp0,"echo %2d\t", i + 1);
		//system(temp0);
		string traceNodeBuf = temp0;
		for (int j = 0; j < 4; j++){
			if (a[i][j].compare("*") == 0 || j==3){
				sprintf(temp1,"%2s\t", a[i][j].c_str());//*
				//temp3 = strcat( temp3 ,temp1);
				traceNodeBuf += temp1;
			}
			else{
				//printf("%sms\t", a[i][j].c_str());//printf输出，c#读取的顺序在最后，误解
				sprintf(temp1, "%2sms\t", a[i][j].c_str());
				traceNodeBuf += temp1;
			}
		}
		sprintf(temp2, "%s\n", traceNodeBuf.c_str());
		system(temp2);
		//system("echo.");//换行
		//printf("\n");
	}
	//实现ping功能
	string IsPing = argv[2];//char转string 直接赋值
	if (IsPing.compare("true") == 0){//要ping 
		for (int i = 0; i < completIndex; i++){
			string PingHost = a[i][3];
			if (PingHost.compare("Request time out.") == 0){
				//printf("No host info.\n");
				//system("echo No host info.\n");
			}
			else{
				string PingStrt = "ping " + PingHost + " -l " + char2str(argv[3]) + " -n " + char2str(argv[4]);
				system("echo tracert-ping");
				system(PingStrt.c_str());
				system("echo.");
			}
			
		}
		
	}
	system("echo.");//换行
	system("echo traceroute complete.");
	system("echo.");//换行
	//system("echo.");//换行
	//
	return 0;
}

void TraceThread(void *p)
{
	//每个tracert线程默认同样ttl请求三次
	HANDLE NodeThreads[3];
	trace_thread* current = (trace_thread*)p;
	for (int index = 0; index < 3; index++){
		//开3个子线程，重复执行
		current->index = index;
		NodeThreads[index] = (HANDLE)_beginthread(NodeThread, 0, current);
		
	}		  
	WaitForMultipleObjects(90, NodeThreads, TRUE, INFINITE);//等待所有线程执行结束后	 
	delete p;
	_endthread();
}
//每个tracert线程默认同样ttl请求三次，获取三次的数据.待优化

void NodeThread(void *p){
	string threadBuf;
	string cp;
	char achReqData[8192];
	for (int i = 0; i<64; i++) achReqData[i] = 32; //whitespaces
	trace_thread* current = (trace_thread*)p;
	IP_OPTION_INFORMATION IpOption;
	ZeroMemory(&IpOption, sizeof(IP_OPTION_INFORMATION));
	IpOption.Ttl = current->ttl;
	int index = current->index;
	//hMutex = CreateMutex(NULL, FALSE, "Test"); //创建互斥量
	int res = IcmpSendEcho(hIcmp, (IPAddr)current->address, SendData, sizeof(SendData), &IpOption, ReplyBuffer, sizeof(ReplyBuffer), 3000);
	//Sleep(3000);//休眠三秒
	//WaitForSingleObject(hMutex, INFINITE); //互斥锁
	WaitForSingleObject(hMutex, INFINITE); //互斥锁
	if (res != 0){

		if (pEchoReply->RoundTripTime == 0){
			//printf("\t<1ms");
			a[IpOption.Ttl - 1][index] = "^<1";//dos中echo特殊符号前面要加^
		}
		else{
			//printf("\t%dms", pEchoReply->RoundTripTime);
			a[IpOption.Ttl - 1][index] = num2str(pEchoReply->RoundTripTime);
		}
		//printf("\t%s\n", inet_ntoa(*(in_addr*)&(pEchoReply->Address)));//ip地址
		if (a[IpOption.Ttl - 1][3].empty()){
			a[IpOption.Ttl - 1][3] = inet_ntoa(*(in_addr*)&(pEchoReply->Address));
		}
		//判断是否完成路由路径探测
		if ((unsigned long)pEchoReply->Address == ip){
			//	printf("\nTrace complete.\n");
			a[IpOption.Ttl - 1][index] = num2str(pEchoReply->RoundTripTime);;
			a[IpOption.Ttl - 1][3] = inet_ntoa(*(in_addr*)&(pEchoReply->Address));
		}
	}
	else{
		//printf("\t*\tRequest time out.\n");
		a[IpOption.Ttl - 1][index] = "*";
		a[IpOption.Ttl - 1][3] = "Request time out.";
	}

	//ReleaseMutex(hMutex); //释放互斥锁 
	ReleaseMutex(hMutex); //释放互斥锁 
	delete p;
	_endthread();
}