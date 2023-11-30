
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "iec61850.h"
#include "json/json.h"
#define BUFFER_LENGTH	2048
#define PORT 12345

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;
FILE *file;
int contador = 0;


void syncTime(int sockfd) {
    struct timeval client_time;

    // Obter tempo local com milissegundos
    gettimeofday(&client_time, NULL);

    // Enviar tempo do cliente ao servidor
    send(sockfd, &client_time, sizeof(client_time), 0);

    // Receber tempo do servidor
    recv(sockfd, &client_time, sizeof(client_time), 0);

    // Converter a estrutura timeval para uma estrutura tm
    struct tm* server_tm = localtime(&client_time.tv_sec);

    // Imprimir a hora formatada com milissegundos
    printf("Tempo recebido do servidor: %02d:%02d:%02d.%05ld\n",
           server_tm->tm_hour, server_tm->tm_min, server_tm->tm_sec, client_time.tv_usec / 100);
}


// Metodo criada para pegar hora atual.
//// FATLOU O SINCRONISMO DE TEMPO COM UMA FONTE CONFIAVEL
char* utc() {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);

		char formattedTime[20];
		strftime(formattedTime, sizeof(formattedTime), "%H:%M:%S", &tm);

		printf("Hora recebimento: %s.%09ld\n", formattedTime, ts.tv_nsec);
}

//// Metodo criado para formatar os dados para salvar no CSV.
char* formatString(int contador, int len, float valor) {
    // Aloca espaço para a string resultante
    char* result = (char*)malloc(256);  // Ajuste o tamanho conforme necessário

    // Obtém o tempo atual
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    struct tm* time_info = gmtime(&current_time.tv_sec);

    // Formata os valores na string
    sprintf(result, "%d-%02d-%02d %02d:%02d:%02d.%06ld,%f,%d,%d",
            1900 + time_info->tm_year, time_info->tm_mon + 1, time_info->tm_mday,
            time_info->tm_hour, time_info->tm_min, time_info->tm_sec,
            current_time.tv_usec, valor, contador, len);
    return result;
}

//// 	Metodo para enviar pacotes SV
void enviarPacoteSV(float valueSV, pcap_t *fp) {
    unsigned char buf[BUFFER_LENGTH] = {0};

	/// definindo samples values
	E1Q1SB1.S1.C1.exampleRMXU_1.AmpLocPhsA.instMag.f = valueSV;
	E1Q1SB1.S1.C1.exampleRMXU_1.AmpLocPhsB.instMag.f = valueSV*2;

	///Loop para percorrer todos os ASDU (0-15)
	int i = 0;
	for (i = 0; i < E1Q1SB1.S1.C1.LN0.rmxuCB.noASDU; i++) {
		len = E1Q1SB1.S1.C1.LN0.rmxuCB.update(buf);
		if (len > 0) {
			contador++;
			/// enviando pacote SV
			utc();
			pcap_sendpacket(fp, buf, len);
			//// utilizado para analise sem CSV.
			//// Metodo para decodificar pacotes SV e Goose ( valida se o modelo foi atualizado corretamente ).
			// gse_sv_packet_filter(buf, len);
			// printf("SV A test: %s\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f == valueSV ? "passed" : "failed");
			// printf("SV B test: %s\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsB.instMag.f == valueSV*2 ? "passed" : "failed");
			
	//// Salvando dados no CSV.		
			// int inputValue = D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f;
			// char* stringFormatada = formatString(contador,len, inputValue);
			// fprintf(file, "%s\n", stringFormatada);
		}

	}

}

/// Inicializando PCAP.
pcap_t *initWinpcap() {
	pcap_t *fpl;
    pcap_if_t *alldevs;
    pcap_if_t *used_if;


	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

    used_if = alldevs;
    fflush(stdout);

	if ((fpl = pcap_open_live(used_if->name,	// name of the device
							 65536,				// portion of the packet to capture. It doesn't matter in this case
							 1,					// promiscuous mode (nonzero means promiscuous)
							 1000,				// read timeout
							 errbuf				// error buffer
							 )) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", alldevs->name);
		exit(2);
	}

	return fpl;
}

int main() {

	int numeroPacotes = 300;
	int pacoteAtual = 0;
	float valueSV = (float) rand() / (float) RAND_MAX;

    int sockfd;
    struct sockaddr_in server_addr;

    // Cria um socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Erro ao criar o socket");
        exit(EXIT_FAILURE);
    }

    // Configura o endereço do servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("192.168.0.2");

    // Conecta-se ao servidor
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erro ao conectar ao servidor");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Mantém a sincronização contínua de tempo
    while (1) {
        syncTime(sockfd);
        sleep(1);  // Aguarda 1 segundo antes de enviar a próxima solicitação
    }

    // Fecha o socket
    close(sockfd);

	// //// Inicializando bibliotecas base.
    // initialise_iec61850();
    // fp = initWinpcap();

	// file = fopen("enviaSV.csv", "a"); // Abre o arquivo para escrita (modo de adição)
	// clock_t inicio = clock();
	// //// loop para envio dos pacotes	
    // while (pacoteAtual <= numeroPacotes) {
    // 	enviarPacoteSV(valueSV, fp);
	// 	usleep(208); // Espera por 208 nanossegundos
	//     pacoteAtual++; 
	// }
    // clock_t fim = clock();
    // double tempoDecorrido = ((double)(fim - inicio)) / CLOCKS_PER_SEC;
    // printf("O programa levou %.6f segundos para executar.\n", tempoDecorrido);

	// fflush(stdout);
	// pcap_close(fp);
	// // fclose(file);

	return 0;
}
