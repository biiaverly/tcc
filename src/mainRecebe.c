#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"
#include <arpa/inet.h>

#define PORT 12345
#define BUFFER_LENGTH	2048

FILE *file;
time_t inicio1, fim1;
int verifica = 0 ;
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;


#define PORT 12345

void syncTime(int client_socket) {
    struct timeval client_time;

    // Receber tempo do cliente
    recv(client_socket, &client_time, sizeof(client_time), 0);

    // Obter tempo atual com milissegundos
    struct timeval server_time;
    gettimeofday(&server_time, NULL);

    // Converter a estrutura timeval para uma estrutura tm
    struct tm* client_tm = localtime(&client_time.tv_sec);
    struct tm* server_tm = localtime(&server_time.tv_sec);

    // Imprimir o tempo recebido do cliente
    printf("Tempo recebido do cliente: %02d:%02d:%02d.%05ld\n",
           client_tm->tm_hour, client_tm->tm_min, client_tm->tm_sec, client_time.tv_usec / 100);

    // Enviar tempo do servidor de volta ao cliente
    send(client_socket, &server_time, sizeof(server_time), 0);

    // Imprimir o tempo enviado de volta ao cliente
    printf("Tempo enviado de volta ao cliente: %02d:%02d:%02d.%05ld\n",
           server_tm->tm_hour, server_tm->tm_min, server_tm->tm_sec, server_time.tv_usec / 100);
}

// Metodo criada para pegar hora atual.
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
char* formatString(char* hora, int contador, int len, float valor) {
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

    // Retorna a string resultante
    return result;
}

static int contador = 0; // Declara um contador como estático para preservar seu valor entre chamadas
static int contadorSV = 0; // Declara um contador como estático para preservar seu valor entre chamadas

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    	
//// Verificando se e um pacote GOOSE.
	if (pkt_data[3] == 0x01) {
		contador++; 
		verifica++;
		/// utilizado para pegar o tempo de inicio da captura.
			/// Nao foi utilizado antes pois o pcap pega varios pacotes alem de GOOSE E SV.
		if(verifica == 1)
		{
			time(&inicio1);

		}
		printf("Pacote %d capturado: %d bytes\n",contador, header->len);

		gse_sv_packet_filter((unsigned char *) pkt_data, header->len);

		/// quando o gse_sv_Paclek_filter nao estava funcionando a variavel foi atualizada manualmente.
		E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
		int length2 = E1Q1SB1.S1.C1.LN0.ItlPositions.send((unsigned char *) pkt_data, 1, 512);  // generate a goose packet, and store the bytes in "buffer"                   // set a value that appears in the dataset used by the "ItlPositions" GOOSE Control
		gse_sv_packet_filter((unsigned char *) pkt_data, length2);
		
		
		float inputValue = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
		printf("Valor %f\n",inputValue);
 
    	// char* hora = utc();
    	// char* stringFormatada = formatString(hora, contador, header->len, inputValue);
		// fprintf(file, "%s\n", stringFormatada);
    }

/// Verificando se e um pacote SV.
	if (pkt_data[3] == 0x04) {
		contadorSV++; // Incrementa o contador dentro do if
		verifica++;
		if(verifica == 1)
		{
			time(&inicio1);

		}
		printf("Pacote SV %d capturado: %d bytes\n",contadorSV, header->len);
		gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
		// printf("SV A test: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f );
		// printf("SV B test: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsB.instMag.f );
			
		// Antes o gse_sv nao estava funcionando entao tive que fazer essa parte para atualizar o valor para validacao.	
		//Todas as analises foram feitas com o codigo a baixo.
		// len = E1Q1SB1.S1.C1.LN0.rmxuCB.update(buf);
		// // printf("len value SV: %d\n", len);
		// int length2 = E1Q1SB1.S1.C1.LN0.ItlPositions.send((unsigned char *) pkt_data, 1, 512);  
		// printf("Valor : %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f);
		// gse_sv_packet_filter((unsigned char *) pkt_data, length2);
		// float inputValue = D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f;

// Salva arquivos no CSV.
    	char* hora = utc();
    	char* stringFormatada = formatString(hora, contadorSV, header->len, D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f);
		fprintf(file, "%s\n", stringFormatada);


    }	

}

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

    //pcap_freealldevs(alldevs);

	return fpl;
}


int main() {
	int len = 0;
	initialise_iec61850();
	fp = initWinpcap();

    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Cria um socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Erro ao criar o socket");
        exit(EXIT_FAILURE);
    }

    // Configura o endereço do servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Liga o socket ao endereço do servidor
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erro ao vincular o socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Aguarda por conexões
    if (listen(server_socket, 1) == -1) {
        perror("Erro ao escutar por conexões");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Aguardando por conexões...\n");

    // Aceita a conexão do cliente
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket == -1) {
        perror("Erro ao aceitar a conexão do cliente");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Mantém a sincronização contínua de tempo
    while (1) {
        syncTime(client_socket);
        sleep(1);  // Aguarda 1 segundo antes de enviar a próxima solicitação
    }

    // Fecha os sockets
    close(client_socket);
    close(server_socket);


	// //Define a quantidade de pacotes a serem capturados.
	// 	/// Goose = 46 e SV = 300
	// int qtPacotes = 300;

	// /// Abrindo arquivo csv em modo adicao.
	// file = fopen("recebe.csv", "a"); // Abre o arquivo para escrita (modo de adição)

	// printf("Inicio captura de pacote: ");
	// while(verifica < qtPacotes){
		
	// 	pcap_loop(fp, 1, packet_handler,NULL);

	// }
	// time(&fim1);

	// clock_t fim = clock();
	// double tempo1 = difftime(fim1, inicio1);
	// printf("Tempo total decorrido: %.6f segundos\n", tempo1);

	// pcap_close(fp);

	// /// Fecha CSV
	// fclose(file);


	return 0;
}