
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
#define SERVER_ADDRESS "192.168.0.17"  // Substitua pelo endereço do servidor

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;
FILE *file;
int contador = 0;
int sockfd; // Descritor do socket




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

//// Metodo criada para pegar hora atual.
//// FATLOU O SINCRONISMO DE TEMPO COM UMA FONTE CONFIAVEL CRIADO O ( synchronizeClock)
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
// Metodo criado para formatar os dados para salvar no CSV.
char* formatString(char* hora,int contador, int len, float valor) {
  // 1. Aloca espaço para a string resultante
    char* result = (char*)malloc(256);  // Ajuste o tamanho conforme necessário

    sprintf(result, "%s,%f,%d,%d",
            hora, valor, contador, len);

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

			pcap_sendpacket(fp, buf, len);
        // Utilizado para validacao.
            // printf("Pacote %d enviado: ",contador)
			// gse_sv_packet_filter(buf, len);
			// printf("SV A test: %s\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsA.instMag.f == valueSV ? "passed" : "failed");
			// printf("SV B test: %s\n", D1Q1SB4.S1.C1.exampleMMXU_1.sv_inputs_rmxuCB.E1Q1SB1_C1_rmxu[15].C1_RMXU_1_AmpLocPhsB.instMag.f == valueSV*2 ? "passed" : "failed");
			
        // 1.2. Escolhendo o metodo e tipo de sincronismo da hora:
            char* hora = synchronizeClock(); // com sincronismo
            // char* hora = utc(); // sem sincronismo
            //----------- M E T O D O      S E M        C S V 
            // printf("Hora envio: %s\n",hora);

            //----------- M E T O D O      C O M        C S V 
            int inputValue = E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f; // define o valor que sera salvo no csv.
            char* stringFormatada = formatString(hora,contador,len, inputValue); // formata os dados para o csv.
            fprintf(file, "%s\n", stringFormatada); // salva os dados no csv.

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

	int numeroPacotes = 299;
	int pacoteAtual = 0;
	float valueSV = (float) rand() / (float) RAND_MAX;

// // -------------------- Metodo de sincronismo de relogio.
    struct sockaddr_in serv_addr;
    // Criação do socket
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("Erro ao criar o socket");
            exit(EXIT_FAILURE);
        }

    // Configuração do endereço do servidor
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        if (inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr) <= 0) {
            perror("Erro ao converter o endereço");
            exit(EXIT_FAILURE);
        }

    // Conversão do endereço IP do servidor para o formato binário
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
            perror("Erro ao conectar");
            exit(EXIT_FAILURE);
        }
	
// // Inicializando bibliotecas base.
    initialise_iec61850();
    fp = initWinpcap();
// // -------------------- Metodo com CSV.
	file = fopen("enviaSV.csv", "a"); // Abre o arquivo para escrita (modo de adição)
// // Envio dos pacotes.	
    clock_t inicio = clock();
	//// loop para envio dos pacotes	
    while (pacoteAtual <= numeroPacotes) {
    	enviarPacoteSV(valueSV, fp);
		usleep(208); // Espera por 208 microsegundos
	    pacoteAtual++; 
	}
    clock_t fim = clock();
    double tempoDecorrido = ((double)(fim - inicio)) / CLOCKS_PER_SEC;
    printf("O programa levou %.6f segundos para executar.\n", tempoDecorrido);

	fflush(stdout);
	pcap_close(fp);
// // ------- Metodo com CSV.
	fclose(file);
// // ------- Metodo com sincronismo de tempo..
    close(sockfd);

	return 0;
}
