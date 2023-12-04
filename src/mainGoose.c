#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"
#define BUFFER_LENGTH	2048


#define PORT 12345
#define SERVER_ADDRESS "192.168.0.17"  // Substitua pelo endereço do servidor
int sockfd; // Descritor do socket

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
FILE *file;
time_t inicio1,fim1;

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

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
}

// Metodo criado para formatar os dados para salvar no CSV.
char* formatString(char* hora,int contador, int len, float valor) {
  // 1. Aloca espaço para a string resultante
    char* result = (char*)malloc(256);  // Ajuste o tamanho conforme necessário

    sprintf(result, "%s,%f,%d,%d",
            hora, valor, contador, len);

    return result;
}

// Metodo criada para pegar hora atual.
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

void enviarPacotesComAtrasos(float valueGSE, pcap_t *fp) {
    
  // 0.  Definindo variaveis iniciais.
	int delay = 1;  
    int max_delay = 50; 
    int len = 0;
	int contador = 1;
    unsigned char buf[BUFFER_LENGTH] = {0};
	// printf("Enviando pacotes com atraso de %d ms\n", 0);

  // 1.  Enviando o primeiro pacote apos um Evento (senf(buf,evento,delay))
    // 1.1. Enviando o primeiro pacote.
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = valueGSE;
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 1, delay); //cria pacote GOOSE e salva no buffer.
	pcap_sendpacket(fp, buf, len);

  // 1.2. Escolhendo o metodo e tipo de sincronismo da hora:
    // char* hora = synchronizeClock(); // com sincronismo
    char* hora = utc(); // sem sincronismo
    //----------- M E T O D O      S E M        C S V 
    // printf("Hora envio: %s\n",hora);

    //----------- M E T O D O      C O M        C S V 
	int inputValue = E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f; // define o valor que sera salvo no csv.
	char* stringFormatada = formatString(hora,contador,len, inputValue); // formata os dados para o csv.
	fprintf(file, "%s\n", stringFormatada); // salva os dados no csv.



  // 2.  Parte transitoria de quando ocorre um evento ate chegar a parte estavel 
    while (delay <= max_delay) {
    // 2.1. Enviando pacotes.
        usleep(delay * 1000); 
		contador++;
		len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 0, delay);

        // printf("Enviando pacotes numero %d com atraso de %d ms\n",contador, delay);
        pcap_sendpacket(fp, buf, len);

    // 2.2. Escolhendo o metodo e tipo de sincronismo da hora:
        // char* hora = synchronizeClock(); // com sincronismo
        char* hora = utc(); // sem sincronismo
        //----------- M E T O D O      S E M        C S V 
        // printf("Hora envio: %s\n",hora);

      // 2.2.2 ----------- M E T O D O      C O M        C S V 
        int inputValue = E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f; // define o valor que sera salvo no csv.
        char* stringFormatada = formatString(hora,contador,len, inputValue); // formata os dados para o csv.
        fprintf(file, "%s\n", stringFormatada); // salva os dados no csv.
    
    // 2.3. Esperando tempo para retransmissao e incremento de tempo.
        delay += 2;  // Incremento de 2ms a cada iteração
    }

  // 3. Parte estacionaria , funcionando como um KEEP ALIVE.
   // 3.0. Definindo variaives iniciais
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = 13800;
	int delayFixo = 50000; 
   // 3.1.  Enviando pacotes delay fixo (send(buf,0,50000))
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 0, delayFixo); 
	for(int cont =0 ; cont < 20 ; cont++){
		int nPacote = contador + cont +1;
		// printf("Enviando pacotes com rede estavel %d \n",nPacote);
        usleep(delayFixo);  // Converte para microssegundos

		pcap_sendpacket(fp, buf, len);

   // 3.2. Escolhendo o metodo e tipo de sincronismo da hora:
        // char* hora = synchronizeClock(); // com sincronismo
        char* hora = utc(); // sem sincronismo
        // ----------- M E T O D O      S E M        C S V 
        // printf("Hora envio: %s\n",hora);
        // ----------- M E T O D O      C O M        C S V 
        int inputValue = E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f; // define o valor que sera salvo no csv.
        char* stringFormatada = formatString(hora,contador,len, inputValue); // formata os dados para o csv.
        fprintf(file, "%s\n", stringFormatada); // salva os dados no csv.
   // 3.3 Esperando o delay para enviar novo pacote.
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
 // 0. Definindo variaveis inicias e inicializando bibiliotecas.
    int len = 0;
    float valueGSE = (float)rand();
    initialise_iec61850();
    fp = initWinpcap();

 // 1. Definindo e configurando socket para sincronismo de tempo.
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


 // 2. Abrindo CSV.
	file = fopen("enviaGoose.csv", "a"); // Abre o arquivo para escrita (modo de adição)
 // 3.  Envia pacotes Goose.
	time(&inicio1);
    enviarPacotesComAtrasos(valueGSE, fp);
	time(&fim1);
 // 4. Analise tempo de processamento.
	double tempo = difftime(fim1,inicio1);
	clock_t fim = clock();
	printf("tempo envio de pacotes %.6f segundos",tempo);
	printf("\n");

 // 5. Encerrando instancias.
	fflush(stdout);
	pcap_close(fp);
	fclose(file);


	return 0;
}