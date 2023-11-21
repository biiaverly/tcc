
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "iec61850.h"
#include "json/json.h"

#define BUFFER_LENGTH	2048
struct timeval inicioProcessamento, fimProcessamento,inicioEnvioPacotes,fimEnvioPacotes,inicioEnvioPacote,fimEnvioPacote;

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char buf[BUFFER_LENGTH] = {0};
int len = 0;
FILE *file;

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

void enviarPacotesComAtrasos(float valueGSE, pcap_t *fp) {

	int delay = 1;  
    int max_delay = 50; 
    int len = 0;
	int contador = 1;
    unsigned char buf[BUFFER_LENGTH] = {0};

	printf("Enviando pacotes com atraso de %d ms\n", 0);

/// Enviando o primeiro pacote apos um Evento.
	/// 1. Setando a tensao no transformador para valueGSE.
	/// 2. Padrao IEC61850: DispositivoFisico.DispositivoLogico.NoLogico.DataObjeto_instancia.DataAtributo
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = valueGSE;
	///3. Gerando um pacote Goose para o GOSECONTROL ItLPositions.
	/// send(buf,1,2) o valor 1 define a mudanca no stNum do pacote Goose,informando a ocorrencia de um evento.
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 1, 2);
	///4. Envio imediato do pacote apos a ocorrencia de um evento.
	pcap_sendpacket(fp, buf, len);

///Salvando o dado no csv.	
	int inputValue = valueGSE;
	char* stringFormatada = formatString(contador,len, inputValue);
	fprintf(file, "%s\n", stringFormatada);

/// Envio de pacotes seguintes apos a ocorrencia de um evento.
    while (delay <= max_delay) {
		contador++;

	/// 1. Gerando um pacote Goose apos a ocorrencia de um evento.
		/// send(buf,0,2) o valor 0 define a mudanca no sqNum.
		len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 0, 2);
	/// 2. Delay para o envio da proxima mensagem.
        usleep(delay * 1000); 
        printf("Enviando pacotes numero %d com atraso de %d ms\n",contador, delay);
	/// 3. Envio do pacote para rede utilizando o pcap.
        pcap_sendpacket(fp, buf, len);
	/// 4. Salvando os dados no excel.
		char* stringFormatada = formatString(contador,len, inputValue);
		fprintf(file, "%s\n", stringFormatada);
	/// 4. Aumentando o tempo de retransmissao em 2ms.
        delay += 2;  
    }

/// Enviando pacotes com delay fixo (keep alive)
    E1Q1SB1.S1.C1.TVTRa_1.Vol.instMag.f = 13800;
	//	1.Definindo o tempo fixo como 50 ms
	int delayFixo = 50000; 
	len = E1Q1SB1.S1.C1.LN0.ItlPositions.send(buf, 0, 2);
	//	2.Envio de 20 pacotes ate fim da aplicacao.
	for(int cont =0 ; cont < 20 ; cont++){
		int nPacote = contador + cont +1;
		printf("Enviando pacotes com rede estavel %d \n",nPacote);
		pcap_sendpacket(fp, buf, len);
		char* stringFormatada = formatString(nPacote,len, inputValue);
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
// Definindo as variaveis iniciais e inicializando rapid61850 e pcap.
    int len = 0;
    float valueGSE = (float)rand();
    initialise_iec61850();
    fp = initWinpcap();

// Criando excel para salvar os dados.
	file = fopen("enviaGoose.csv", "a"); 

// Metodo para enviar pacotes de acordo com a norma IEC61850.
    enviarPacotesComAtrasos(valueGSE, fp);

	fflush(stdout);
	pcap_close(fp);
	fclose(file);
	return 0;
}
