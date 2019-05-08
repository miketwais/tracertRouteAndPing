#pragma warning(disable:4996)
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <cstdlib>
#include <IPHlpApi.h>
#include <process.h>
#include "tracert.h"
#include <iostream>  
#include <sstream>    //ʹ��stringstream��Ҫ�������ͷ�ļ�  
#include <string>
using  std::string;
using  std::wstring;
using namespace std;
//���Ӿ�̬���ӿ�ws2_32.lib
#pragma comment(lib,"ws2_32.lib")
//����3���������͵�ָ��
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
struct trace_thread { //tracert�߳̽ṹ��
	int			address;
	int			ttl;
	int			index;
};

//����3������ָ��
lpIcmpCreateFile IcmpCreateFile;
lpIcmpCloseHandle IcmpCloseHandle;
lpIcmpSendEcho IcmpSendEcho;
//��ICMP���
HANDLE hIcmp;
//����IP��ͷ��TTLֵ
//IP_OPTION_INFORMATION IpOption;
//����Ҫ���͵�����
char SendData[32];
//���ý��ջ�����
char ReplyBuffer[sizeof(ICMP_ECHO_REPLY)+32];
PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
BOOL bLoop = TRUE;
void TraceThread(void *p);
void NodeThread(void *p);
unsigned long ip;
string a[30][4];//��ά���������洢���
HANDLE hMutex = NULL; //������  
//longתstring
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

//char*תstring 
string char2str(char* i)
{
	string res;
	res = i;
	return res;
}
//�����������ip
string GetIP(LPCSTR pszName)
{
	HOSTENT* pHE = ::gethostbyname(pszName);
	if (NULL == pHE) return "";
	return inet_ntoa(*((in_addr*)pHE->h_addr_list[0]));
}
int main(int argc, char* argv[]){
	//��tracertTest.exe����ֱ�ӽ����ĸ�������char host,bool IsPing, int -l,int -n���磺www.baidu.com true 10 10
	//if (argc != 4){//Ϊ�����Ʋ�������Ϊ4
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
	//system("echo.");//����
	
	char temp[100];
	//char *buf;
	//argv[1] = "10.20.21.244";
	//ת��IP��ַ������
	ip = inet_addr(argv[1]);//��һ�����ʮ���Ƶ�IPת����һ��������������u_long���ͣ�
	if (ip == INADDR_NONE){//�����ж�������ǲ���ip��ַ,inet_addrʧ��ʱ����INADDR_NONE
		//�û����������������
		hostent* pHost = gethostbyname(argv[1]);//���ض�Ӧ�ڸ����������İ����������ֺ͵�ַ��Ϣ��hostent�ṹ��ָ��
		//��������޷�����
		if (pHost == NULL){
			printf("Invalid IP or domain name: %s\n", argv[1]);
			exit(-1);
		}
		//ȡ�����ĵ�һ��IP��ַ
		ip = *(unsigned long*)pHost->h_addr_list[0];
		sprintf(temp, "echo traceroute to %s(%s):\n\n", char2str(argv[1]).c_str(), char2str(inet_ntoa(*(in_addr*)&ip)).c_str());
	}
	else{
		sprintf(temp, "echo traceroute to %s:\n\n", char2str(argv[1]).c_str());
	}
	system(temp);
	system("echo.");//����
	//����ICMP.DLL��̬��
	HMODULE hIcmpDll = ::LoadLibraryEx(TEXT("icmp.dll"), NULL, 0);
	//HMODULE hIcmpDll = LoadLibrary("icmp.dll");
	if (hIcmpDll == NULL){
		printf("fail to load icmp.dll\n");
		exit(-1);
	}
	
	//��ICMP.DLL�л�ȡ����ĺ�����ڵ�ַ
	IcmpCreateFile = (lpIcmpCreateFile)GetProcAddress(hIcmpDll, "IcmpCreateFile");
	IcmpCloseHandle = (lpIcmpCloseHandle)GetProcAddress(hIcmpDll, "IcmpCloseHandle");
	IcmpSendEcho = (lpIcmpSendEcho)GetProcAddress(hIcmpDll, "IcmpSendEcho");
	
	if ((hIcmp = IcmpCreateFile()) == INVALID_HANDLE_VALUE){
		printf("\tUnable to open ICMP file.\n");
		exit(-1);
	}
	

	memset(SendData, '0', sizeof(SendData));
	//void *memset(void *s,int c,size_t n)
	//�ܵ����ã����ѿ����ڴ�ռ� s ���� n ���ֽڵ�ֵ��Ϊֵ c��
	
	
	int iMaxHop = 30;
	//typedef void **HANDLE;
	//���߳�ʵ��
	HANDLE hThreads[90];
	hMutex = CreateMutex(NULL, FALSE, "Test"); //����������
	// one thread per TTL value
	for (int i = 0; i < iMaxHop; i++) {
		for (int j = 0; j < 3; j++){
			trace_thread *current = new trace_thread;
			current->address = inet_addr(inet_ntoa(*(in_addr*)&ip));
			current->ttl = i + 1;
			current->index = j;
			hThreads[i] = (HANDLE)_beginthread(NodeThread, 0, current);//����ʲô���񣬶�����30��Tracert�̣߳����30��Ծ�㣩����Ȼÿ���̵߳�ttl����1
			Sleep(20);
		}
	}
	//Sleep(3000);//����
	//CloseHandle(hThreads);
	WaitForMultipleObjects(90, hThreads, TRUE, INFINITE);//�ȴ������߳�ִ�н�����,�������Ǵ����ʹ�ã�����
	IcmpCloseHandle(hIcmp);
	FreeLibrary(hIcmpDll);
	WSACleanup();

	//���������ظ������������
	int completIndex;
	for (int k = 0; k < 30; k++){
		//��strcmp(aa1.c_str(),bb2.c_str())==0��ʾ��ȡ�
		if (a[k][3].compare(inet_ntoa(*(in_addr*)&(ip))) == 0){
			/*if (k == 0){
				completIndex = 0;
			}
			else{*/
				completIndex = k;//��k�ڵ㴦complete tracert!
			//}
			break;
		}
		else{
			completIndex = 29;//��Ժ�����ȫ��ͨ�����
		}
	}
	completIndex++;//����1
	char temp0[40],temp1[40], temp2[100];
	for (int i = 0; i < completIndex; i++){     //�������е�Ԫ��ȫ�����
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
				//printf("%sms\t", a[i][j].c_str());//printf�����c#��ȡ��˳����������
				sprintf(temp1, "%2sms\t", a[i][j].c_str());
				traceNodeBuf += temp1;
			}
		}
		sprintf(temp2, "%s\n", traceNodeBuf.c_str());
		system(temp2);
		//system("echo.");//����
		//printf("\n");
	}
	//ʵ��ping����
	string IsPing = argv[2];//charתstring ֱ�Ӹ�ֵ
	if (IsPing.compare("true") == 0){//Ҫping 
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
	system("echo.");//����
	system("echo traceroute complete.");
	system("echo.");//����
	//system("echo.");//����
	//
	return 0;
}

void TraceThread(void *p)
{
	//ÿ��tracert�߳�Ĭ��ͬ��ttl��������
	HANDLE NodeThreads[3];
	trace_thread* current = (trace_thread*)p;
	for (int index = 0; index < 3; index++){
		//��3�����̣߳��ظ�ִ��
		current->index = index;
		NodeThreads[index] = (HANDLE)_beginthread(NodeThread, 0, current);
		
	}		  
	WaitForMultipleObjects(90, NodeThreads, TRUE, INFINITE);//�ȴ������߳�ִ�н�����	 
	delete p;
	_endthread();
}
//ÿ��tracert�߳�Ĭ��ͬ��ttl�������Σ���ȡ���ε�����.���Ż�

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
	//hMutex = CreateMutex(NULL, FALSE, "Test"); //����������
	int res = IcmpSendEcho(hIcmp, (IPAddr)current->address, SendData, sizeof(SendData), &IpOption, ReplyBuffer, sizeof(ReplyBuffer), 3000);
	//Sleep(3000);//��������
	//WaitForSingleObject(hMutex, INFINITE); //������
	WaitForSingleObject(hMutex, INFINITE); //������
	if (res != 0){

		if (pEchoReply->RoundTripTime == 0){
			//printf("\t<1ms");
			a[IpOption.Ttl - 1][index] = "^<1";//dos��echo�������ǰ��Ҫ��^
		}
		else{
			//printf("\t%dms", pEchoReply->RoundTripTime);
			a[IpOption.Ttl - 1][index] = num2str(pEchoReply->RoundTripTime);
		}
		//printf("\t%s\n", inet_ntoa(*(in_addr*)&(pEchoReply->Address)));//ip��ַ
		if (a[IpOption.Ttl - 1][3].empty()){
			a[IpOption.Ttl - 1][3] = inet_ntoa(*(in_addr*)&(pEchoReply->Address));
		}
		//�ж��Ƿ����·��·��̽��
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

	//ReleaseMutex(hMutex); //�ͷŻ����� 
	ReleaseMutex(hMutex); //�ͷŻ����� 
	delete p;
	_endthread();
}