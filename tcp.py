import asyncio
from os import urandom
from tcputils import *
from time import time

FLAGS_FIN = 1<<0
FLAGS_SYN = 1<<1
FLAGS_RST = 1<<2
FLAGS_ACK = 1<<4

class Timer:
    def __init__(self, timeout, callback):
        self._callback = callback
        self._timeout = timeout
        self._task = None
          
    def start(self):
        self.stop()
        self._task = asyncio.get_event_loop().call_later(self._timeout, self._callback)
  
    def stop(self):
        if self._task != None:
            self._task.cancel()
    
    def update_timer(self, timeout):
        self._timeout = timeout
        


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            conexao._hand_shake(seq_no)
            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                conexao = self.conexoes.pop(id_conexao)
                conexao._end_connection()
            # Passa para a conexão adequada se ela já estiver estabelecida
            else:
                self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))
    
    def random_no(self):
        return struct.unpack('I', urandom(4))
    

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_sender):
        #self.ack_no_raw = servidor.random_no()[0]
        self.seq_no_raw = servidor.random_no()[0]
        self.seq_no = self.seq_no_raw
        self.ack_no = 0

        self._buffer = []
        self._send_base = self.seq_no_raw

        self._timer = None
        self._time_interval = 0.5
        self._estimatedRTT = 0
        self._devRTT = 0
        self._first_sampleRTT = True

        self._queue = []

        self._win_frontier = self._send_base + MSS
        self._cwnd_size = MSS

        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None    

    def _ack_handler(self, ack_no):
        if ack_no <= self._send_base: return
        if len(self._buffer) == 0: return
        if self._timer == None: return

        '''if ack_no >= self._win_frontier:
            self._additive_increase()'''

        self._search_segment_in_buffer(ack_no)
        
        if len(self._buffer) > 0:
            self._timer.start() 
        else:
            self._timer.stop()
            self._timer = None

    def _additive_increase(self):
        self._cwnd_size += MSS
        self._win_frontier = self._send_base + self._cwnd_size

    def _calc_timeout(self, t0):
        sampleRTT = time() - t0
        print('SampleRTT: ', sampleRTT)

        if self._first_sampleRTT:
            self._calc_timeout_first_time(sampleRTT)
            
        else:
            alpha = 0.125
            self._estimatedRTT = (1 - alpha)*self._estimatedRTT + alpha*sampleRTT

            beta = 0.25
            self._devRTT = (1 - beta)*self._devRTT + beta*abs(sampleRTT - self._estimatedRTT)

        self._time_interval = self._estimatedRTT + 4*self._devRTT
        self._timer.update_timer(self._time_interval)
    
    def _calc_timeout_first_time(self, sampleRTT):
        self._estimatedRTT = sampleRTT
        self._devRTT = sampleRTT/2
        self._first_sampleRTT = False
    
    def _end_connection(self):
        self.callback(self, b'')
        self.ack_no += 1
        self._send_ack()
    
    def _hand_shake(self, seq_no_sender):
        self.ack_no = seq_no_sender + 1

        dest_addr, dest_port, src_addr, src_port = self.id_conexao
        header = make_header(src_port, dest_port, self.seq_no, self.ack_no, FLAGS_ACK | FLAGS_SYN)
        segment = fix_checksum(header, src_addr, dest_addr)

        self.servidor.rede.enviar(segment, dest_addr)
        self.seq_no += 1
    
    def _multiplicative_decrease(self):
        self._cwnd_size = max(1, self._cwnd_size // 2)
        self._win_frontier = self._send_base + self._cwnd_size
    
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        if seq_no != self.ack_no: return   # Ignora segmentos errados e fora de ordem
        if ((flags & FLAGS_ACK) == FLAGS_ACK) and (payload == b''):
            self._ack_handler(ack_no)
            return  # Impede responder ACKS com outros ACKs
    
        self.callback(self, payload)
        self.ack_no = seq_no + len(payload)
        self._send_ack()

        print('recebido payload: %r' % payload)
    
    def _retransmit(self):
        #self._multiplicative_decrease()
        if self._timer == None: return
        header, payload, src_addr, dest_addr, seq, t0, _ = self._buffer[0]
        self._buffer[0] = (header, payload, src_addr, dest_addr, seq, t0, False) 
        #dados, dest_addr, _, _, _ = self._buffer[0]
        segment = fix_checksum(header + payload, src_addr, dest_addr)
        self.servidor.rede.enviar(segment, dest_addr)
        self._timer.start()
    
    def _search_segment_in_buffer(self, ack_no):
        self._send_base = ack_no
        for i in range(len(self._buffer)):
            _, payload,_, _, seq, t0, is_first = self._buffer[i]
            if seq == ack_no:
                if is_first:
                    self._calc_timeout(t0)

                self._buffer = self._buffer[i+1:]
                
                return
    
    def _send_ack(self):
        dest_addr, dest_port, src_addr, src_port = self.id_conexao
        header = make_header(src_port, dest_port, self.seq_no, self.ack_no, FLAGS_ACK)
        segment = fix_checksum(header, src_addr, dest_addr)

        self.servidor.rede.enviar(segment, dest_addr)

    ''' Os métodos abaixo fazem parte da API '''

    def enviar(self, dados=b''):
        """
        Usado pela camada de aplicação para enviar dados
        """
        dest_addr, dest_port, src_addr, src_port = self.id_conexao

        while len(dados) > 0:
            mss = self._cwnd_size
            payload = dados[:mss]

            header = make_header(src_port, dest_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header + payload, src_addr, dest_addr)

            t0 = time()
            self.servidor.rede.enviar(segment, dest_addr)

            self.seq_no += len(payload)

            self._buffer.append((header, payload, src_addr, dest_addr, self.seq_no, t0, True))  # Passei pra ca pois quando receber o ACK eu vou comparar com o seq atualizado
            dados = dados[mss:]
        
        if self._timer == None:
            self._timer = Timer(self._time_interval, self._retransmit)
            self._timer.start()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        dest_addr, dest_port, src_addr, src_port = self.id_conexao

        header = make_header(src_port, dest_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segment = fix_checksum(header, src_addr, dest_addr)

        self.servidor.rede.enviar(segment, dest_addr)


    def registrar_recebedor(self, callback):
        self.callback = callback