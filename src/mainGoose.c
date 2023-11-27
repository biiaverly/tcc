
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"
#define BUFFER_LENGTH	2048

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
FILE *file;
time_t inicio1,fim1;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
}

char* formatString( int contador, int len, float valor) {
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
char* utc() {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);

		char formattedTime[20];
		strftime(formattedTime, sizeof(formattedTime), "%H:%M:%S", &tm);

		printf("Hora recebimento: %s.%09ld\n", formattedTime, ts.tv_nsec);
}
void enviarPacotesComAtrasos(float valueGSE, pcap_t *fp) {

	int delay = 1;  
    int max_delay = 50; 
    int len = 0;
	int contador = 1;
    unsigned char buf[BUFFER_LENGTH] = {0};

	printf("Enviando pacotes com atraso de %d ms\n", 0);

/// Enviando o primeiro pacote apos um Evento (senf(buf,1,2))
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = valueGSE;
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 1, 2);
	pcap_sendpacket(fp, buf, len);
	utc();		
///Salvando o dado no csv.	
	int inputValue = E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f;
	char* stringFormatada = formatString(contador,len, inputValue);
	fprintf(file, "%s\n", stringFormatada);

/// Parte transitoria de quando ocorre um evento ate chegar a parte estavel 
    while (delay <= max_delay) {
		contador++;
		len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 0, delay);

        usleep(delay * 1000);  // Converte para microssegundos
        printf("Enviando pacotes numero %d com atraso de %d ms\n",contador, delay);
        pcap_sendpacket(fp, buf, len);
		utc();		

		char* stringFormatada = formatString(contador,len, inputValue);
		fprintf(file, "%s\n", stringFormatada);

        delay += 2;  // Incremento de 2ms a cada iteração
    }

/// Enviando pacotes com delay fixo (keep alive)
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = 13800;
//	Definindo o tempo fixo como 50 ms
	int delayFixo = 50000; 
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 0, delayFixo);
	for(int cont =0 ; cont < 20 ; cont++){
		int nPacote = contador + cont +1;
		printf("Enviando pacotes com rede estavel %d \n",nPacote);
		pcap_sendpacket(fp, buf, len);
		char* stringFormatada = formatString(nPacote,len, 13800);
		fprintf(file, "%s\n", stringFormatada);
		usleep(delayFixo);  // Converte para microssegundos

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
    float valueGSE = (float)rand();
    initialise_iec61850();
    fp = initWinpcap();

	file = fopen("enviaGoose.csv", "a"); // Abre o arquivo para escrita (modo de adição)

	clock_t inicio = clock();

	time(&inicio1);
    enviarPacotesComAtrasos(valueGSE, fp);
	time(&fim1);
	double tempo = difftime(fim1,inicio1);
	clock_t fim = clock();
	// double tempo = ((double)(fim-inicio))/CLOCKS_PER_SEC;
	printf("tempo envio de pacotes %.6f segundos",tempo);
	printf("\n");

	fflush(stdout);
	pcap_close(fp);
	fclose(file);


	return 0;
}
