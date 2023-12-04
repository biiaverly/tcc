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
#define SERVER_ADDRESS "192.168.0.17"  // Substitua pelo endereço do servidor

FILE *file;
time_t inicio1, fim1;
int verifica = 0 ;
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;
int sockfd;
static int contador = 0; // Declara um contador como estático para preservar seu valor entre chamadas
static int contadorSV = 0; // Declara um contador como estático para preservar seu valor entre chamadas

///// Metodo criado para pegar a hora do notebook e testar o escorregamento dos relogios.
char* synchronizeClock() {
    struct timeval tv;
 
    // Solicita o tempo ao servidor
        char request[] = "GET_TIME";
        if (write(sockfd, request, sizeof(request)) == -1) {
            perror("Erro ao solicitar o tempo ao servidor");
            exit(EXIT_FAILURE);
        }

    // Recebe o tempo do servidor
        if (read(sockfd, &tv, sizeof(struct timeval)) == -1) {
            perror("Erro ao receber o tempo do servidor");
            exit(EXIT_FAILURE);
        }

    // Aloca espaço para a string resultante
        char* formattedTime = (char*)malloc(32);  // Ajuste o tamanho conforme necessário

        sprintf(formattedTime, "%02d:%02d:%02d.%06ld",
                localtime(&tv.tv_sec)->tm_hour,
                localtime(&tv.tv_sec)->tm_min,
                localtime(&tv.tv_sec)->tm_sec,
                tv.tv_usec);

    return formattedTime;
}

 // Foi criado o metodo de sincronismo para tentar mitidar o escorregamento do tempo.
char* utc() {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);

        char* formattedTime = (char*)malloc(30); // Adjust the size as needed

        if (formattedTime == NULL) {
            perror("Error allocating memory");
            exit(EXIT_FAILURE);
        }

        // Format the time into the allocated memory
        strftime(formattedTime, 30, "%Y-%m-%d %H:%M:%S", &tm);
        sprintf(formattedTime + strlen(formattedTime),".%5ld",ts.tv_nsec/1000);
        return formattedTime;
}

//// Metodo criado para formatar os dados para salvar no CSV.
char* formatString(char* hora, int contador, int len, float valor) {
    // Aloca espaço para a string resultante
    char* result = (char*)malloc(256);  // Ajuste o tamanho conforme necessário

	sprintf(result, "%s,%f,%d,%d",
			hora, valor, contador, len);
return result;
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    	
 // 1. Verificando se e um pacote GOOSE.
	if (pkt_data[3] == 0x01) 
	{
	// 1.1- Inicializando as variaveis.
		contador++; 
		verifica++;
		if(verifica == 1)
		{
			time(&inicio1);
		}
		gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
		// printf("Pacote %d capturado: %d bytes\n",contador, header->len);
		// /// quando o gse_sv_Paclek_filter nao estava funcionando a variavel foi atualizada manualmente.
		// E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
		// int length2 = E1Q1SB1.S1.C1.LN0.ItlPositions.send((unsigned char *) pkt_data, 1, 512);  // generate a goose packet, and store the bytes in "buffer"                   // set a value that appears in the dataset used by the "ItlPositions" GOOSE Control
		// gse_sv_packet_filter((unsigned char *) pkt_data, length2);

	// 1.2. Escolhendo o metodo e tipo de sincronismo da hora:
		// char* hora = synchronizeClock(); // com sincronismo
		char* hora = utc(); // sem sincronismo

	   // ----------- M E T O D O      S E M        C S V 
		// printf("Hora envio: %s\n",hora);

	   //----------- M E T O D O      C O M        C S V
		
		float inputValue = D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f;
    	char* stringFormatada = formatString(hora, contador, header->len, D1Q1SB4.S1.C1.RSYNa_1.gse_inputs_ItlPositions.E1Q1SB1_C1_Positions.C1_TVTR_1_Vol_instMag.f);
		fprintf(file, "%s\n", stringFormatada);
    }

 // 2. Verificando se e um pacote SV.
	if (pkt_data[3] == 0x04) {
	// 2.1. Inicializando variaveis
		// printf("Pacote %d capturado:",contadorSV);
		contadorSV++; 
		verifica++; /// variavel para monitorar se e o primeiro pacote pacturado para saber o tempo de execucao.
		if(verifica == 1)
		{
			time(&inicio1);

		}

	// 2.2. Escolhendo o metodo e tipo de sincronismo da hora:
	   // ----------- M E T O D O      S E M        C S V 
		char* hora = synchronizeClock(); // com sincronismo
		// char* hora = utc(); // sem sincronismo
		// printf("Hora envio: %s\n",hora);

	   //----------- M E T O D O      C O M        C S V 
		// char* hora = synchronizeClock(); // com sincronismo
		// char* hora = utc(); // sem sincronismo

	// 2.3 Processamento do pacote ( atualizando modelo de dados )
		gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
		// printf("Pacote SV %d capturado: %d bytes",contadorSV, header->len);
		// printf("SV A test: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f );
		// printf("SV B test: %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsB.instMag.f );
			
		// Antes o gse_sv nao estava funcionando entao tive que fazer essa parte para atualizar o valor para validacao.	
		//Todas as analises foram feitas com o codigo a baixo.
		// len = E1Q1SB1.S1.C1.LN0.rmxuCB.update(buf);
		// // printf("len value SV: %d\n", len);
		// int length2 = E1Q1SB1.S1.C1.LN0.ItlPositions.send((unsigned char *) pkt_data, 1, 512);  
		// printf("Valor : %f\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f);
		// gse_sv_packet_filter((unsigned char *) pkt_data, length2);

	// 2.4. Salvando no CSV. 
		float inputValue = D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f;
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
 // 0. Inicializando variaveis.
	int len = 0;
	initialise_iec61850();
	fp = initWinpcap();

	// 1.1. Define a quantidade de pacotes a serem capturados.Goose = 46 e SV = 300
	int qtPacotes = 300;

 // 1. Definindo e configurando socket para sincronismo de tempo.
    struct sockaddr_in serv_addr;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Erro ao criar o socket");
        exit(EXIT_FAILURE);
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr) <= 0) {
        perror("Erro ao converter o endereço");
        exit(EXIT_FAILURE);
    }
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("Erro ao conectar");
        exit(EXIT_FAILURE);
    }

 // 2. Abrindo CSV.
	file = fopen("recebe.csv", "a"); // Abre o arquivo para escrita (modo de adição)

 // 3. Recebe Pacote.
	printf("Inicio captura de pacote: ");
	while(verifica < qtPacotes){
		
		pcap_loop(fp, 1, packet_handler,NULL);

	}
 // 4. Analise tempo de processamento.
	time(&fim1);
	clock_t fim = clock();
	double tempo1 = difftime(fim1, inicio1);
	printf("Tempo total decorrido: %.6f segundos\n", tempo1);

 // 5. Encerrando instancias.
	pcap_close(fp);
	fclose(file);
    close(sockfd);

	return 0;
}