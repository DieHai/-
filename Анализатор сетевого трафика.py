import sys; from scapy.arch.windows import get_windows_if_list; import platform; import os; from collections import *
from datetime import *; from scapy.all import *; from scapy.layers.inet import *; from PyQt5.QtWidgets import *
from PyQt5.QtCore import *; import pyqtgraph as pg; from pyqtgraph import *
class PacketSnifferThread(QThread):
    packet_received = pyqtSignal(object)
    stopped = pyqtSignal()
    def __init__(self, interface=None, filter_exp=None):
        super().__init__()
        self.interface = interface
        self.filter_exp = filter_exp
        self.running = False
        self.socket = None
    def run(self):
        self.running = True
        try:
            sniff(iface=self.interface, filter=self.filter_exp, 
                  prn=self.han_pac_packet, store=False, stop_filter=self.should_stop,
                  timeout=1)
        finally:
            self.stopped.emit()
    def han_pac_packet(self, packet):
        if self.running:
            self.packet_received.emit(packet)
    def should_stop(self, _):
        return not self.running
    def stop(self):
        self.running = False
        self.wait(1000)
class NetworkTrafficAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Анализатор сетевого трафика")
        self.setGeometry(100, 100, 1200, 800)
        self.packets = []
        self.protocol_stats = defaultdict(int)
        self.total_packets = 0
        self.total_bytes = 0
        self.sniffer_thread = None
        self.init_ui()      
        self.update_interfaces()     
    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        control_group = QGroupBox("Управление захватом")
        control_layout = QHBoxLayout()   
        self.interface_combo = QComboBox()
        self.interface_combo.setToolTip("Выберите сетевой интерфейс")       
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("BPF фильтр (например, 'tcp port 80')")      
        self.start_button = QPushButton("Старт")
        self.start_button.clicked.connect(self.start_capture)    
        self.stop_button = QPushButton("Стоп")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)   
        control_layout.addWidget(QLabel("Интерфейс:"))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(QLabel("Фильтр:"))
        control_layout.addWidget(self.filter_edit)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_group.setLayout(control_layout)   
        main_layout.addWidget(control_group)  
        tab_widget = QTabWidget()   
        packets_tab = QWidget()
        packets_layout = QVBoxLayout() 
        self.packets_table = QTableWidget()
        self.packets_table.setColumnCount(7)
        self.packets_table.setHorizontalHeaderLabels(["№", "Время", "Источник", "Назначение", "Протокол", "Длина", "Информация"])
        self.packets_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packets_table.setSelectionMode(QTableWidget.SingleSelection)
        self.packets_table.cellClicked.connect(self.show_packet_details)
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        packets_layout.addWidget(self.packets_table)
        packets_layout.addWidget(QLabel("Детали пакета:"))
        packets_layout.addWidget(self.packet_details)
        packets_tab.setLayout(packets_layout)
        tab_widget.addTab(packets_tab, "Пакеты")
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()
        stats_info_layout = QHBoxLayout()
        self.stats_info = QTextEdit()
        self.stats_info.setReadOnly(True)
        self.protocol_plot = PlotWidget()
        self.protocol_plot.setTitle("Распределение по протоколам")
        stats_info_layout.addWidget(self.stats_info, stretch=2)
        stats_info_layout.addWidget(self.protocol_plot, stretch=3)
        stats_layout.addLayout(stats_info_layout)
        stats_tab.setLayout(stats_layout)       
        tab_widget.addTab(stats_tab, "Статистика")        
        main_layout.addWidget(tab_widget)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)                
    def update_interfaces(self):
        self.interface_combo.clear()        
        try:
            if platform.system() == "Windows":
                try:
                    interfaces = [iface['name'] for iface in get_windows_if_list()]
                    interfaces = [iface for iface in interfaces if not iface.lower().startswith('loopback')]
                except Exception as e:
                    print(f"Ошибка получения интерфейсов Windows: {e}")
                    interfaces = ["Ethernet", "Wi-Fi"]
            else:
                try:
                    interfaces = os.listdir('/sys/class/net/')
                except Exception as e:
                    print(f"Ошибка получения интерфейсов Linux: {e}")
                    interfaces = ["eth0", "wlan0", "lo"]                    
            for iface in interfaces:
                self.interface_combo.addItem(iface)               
            if not interfaces:
                self.interface_combo.addItem("eth0" if platform.system() != "Windows" else "Ethernet")               
        except Exception as e:
            print(f"Критическая ошибка получения интерфейсов: {e}")
            self.interface_combo.addItem("eth0" if platform.system() != "Windows" else "Ethernet")   
    def start_capture(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            return            
        interface = self.interface_combo.currentText()
        filter_exp = self.filter_edit.text()        
        if not interface:
            return           
        self.packets = []
        self.protocol_stats.clear()
        self.total_packets = 0
        self.total_bytes = 0
        self.packets_table.setRowCount(0)
        self.packet_details.clear()       
        self.sniffer_thread = PacketSnifferThread(interface, filter_exp)
        self.sniffer_thread.packet_received.connect(self.process_packet)
        self.sniffer_thread.stopped.connect(self.on_sniffer_stopped)
        self.sniffer_thread.start()       
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)        
    def on_sniffer_stopped(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.update_stats()       
    def stop_capture(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()       
    def process_packet(self, packet):
        self.total_packets += 1       
        packet_info = {
            'number': self.total_packets,
            'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src': '',
            'dst': '',
            'protocol': '',
            'length': len(packet),
            'info': '',
            'raw': packet
        }       
        if IP in packet:
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst          
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                flags = []
                if packet[TCP].flags & 0x01: flags.append('FIN')
                if packet[TCP].flags & 0x02: flags.append('SYN')
                if packet[TCP].flags & 0x04: flags.append('RST')
                if packet[TCP].flags & 0x08: flags.append('PSH')
                if packet[TCP].flags & 0x10: flags.append('ACK')
                if packet[TCP].flags & 0x20: flags.append('URG')
                packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} [{' '.join(flags)}]"                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport}"              
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"                
            else:
                packet_info['protocol'] = 'Other IP'               
        else:
            packet_info['protocol'] = 'Non-IP'            
        self.protocol_stats[packet_info['protocol']] += 1
        self.total_bytes += packet_info['length']        
        self.packets.append(packet_info)        
        self.update_packets_table(packet_info)        
        if self.total_packets % 10 == 0:
            self.update_stats()    
    def update_packets_table(self, packet_info):
        row = self.packets_table.rowCount()
        self.packets_table.insertRow(row)
        self.packets_table.setItem(row, 0, QTableWidgetItem(str(packet_info['number'])))
        self.packets_table.setItem(row, 1, QTableWidgetItem(packet_info['time']))
        self.packets_table.setItem(row, 2, QTableWidgetItem(packet_info['src']))
        self.packets_table.setItem(row, 3, QTableWidgetItem(packet_info['dst']))
        self.packets_table.setItem(row, 4, QTableWidgetItem(packet_info['protocol']))
        self.packets_table.setItem(row, 5, QTableWidgetItem(str(packet_info['length'])))
        self.packets_table.setItem(row, 6, QTableWidgetItem(packet_info['info']))       
        self.packets_table.scrollToBottom()
    def show_packet_details(self, row):
        if 0 <= row < len(self.packets):
            packet = self.packets[row]['raw']
            self.packet_details.setText(packet.show(dump=True))
    def update_stats(self):
        stats_text = f"Всего пакетов: {self.total_packets}\n"
        stats_text += f"Всего данных: {self.total_bytes} байт\n\n"
        stats_text += "По протоколам:\n"       
        for protocol, count in sorted(self.protocol_stats.items()):
            stats_text += f"{protocol}: {count} ({count/self.total_packets:.1%})\n"           
        self.stats_info.setText(stats_text)       
        self.update_protocol_plot()   
    def update_protocol_plot(self):
        self.protocol_plot.clear()       
        if not self.protocol_stats:
            text = pg.TextItem("Нет данных для отображения", anchor=(0.5, 0.5))
            self.protocol_plot.addItem(text)
            return           
        protocols = []
        counts = []        
        for proto, count in self.protocol_stats.items():
            if count > 0:
                protocols.append(proto)
                counts.append(count)      
        if not counts:
            return       
        try:
            bg = pg.BarGraphItem(x=range(len(protocols)), height=counts, width=0.6, 
                                labels=protocols, brush='b')
            self.protocol_plot.addItem(bg)          
            axis = self.protocol_plot.getAxis('bottom')
            axis.setTicks([[(i, proto) for i, proto in enumerate(protocols)]])           
            self.protocol_plot.setLabel('left', "Количество пакетов")
            self.protocol_plot.setTitle("Распределение по протоколам")           
        except Exception as e:
            print(f"Ошибка при создании графика: {e}")
            text = pg.TextItem("Ошибка построения графика", anchor=(0.5, 0.5))
            self.protocol_plot.addItem(text)        
    def closeEvent(self, event):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait(10000)
        event.accept()
if __name__ == "__main__":
    app = QApplication(sys.argv)
    analyzer = NetworkTrafficAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())