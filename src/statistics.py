##################################################
## Print out statistics of the modification detection for the given pcap file
##################################################
## File: statistics.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import time
import math
from xml.etree import ElementTree as ET

class Statistics():
    '''
    Class for handling results of modification detections and statistics
    '''
    def __init__(self, pcap_path, packet_count, pcap_modifications, packet_modifications, start_time, misc_tests):
        '''
        Initialize the class
        Args:

        Returns:
        '''
        self.pcap_path = pcap_path
        self.packet_count = packet_count
        self.pcap_modifications = pcap_modifications
        self.packet_modifications = packet_modifications
        self.misc_tests = misc_tests
        self.time = self.get_total_time(start_time)
        self.function_context = self.get_function_context()

        avg = self.get_weighted_average()
        self.probability = self.get_probability(avg)

    def get_total_time(self, start_time):
        '''
        Get total time of the detection
        Args:
            start_time: start time of the detection

        Returns:
            total_time: total time of the detection
        '''
        total_time = time.time() - start_time
        time_units = [('seconds', 60), ('minutes', 60), ('hours', 24)]
        unit = ''
        for u, multiplier in time_units:
            if total_time < multiplier:
                unit = u
                break
            total_time /= multiplier

        return (f"{total_time:.2f} {unit}")

    def get_function_context(self):
        '''
        Get friendly function names
        Args:

        Returns:
            function_context: friendly function names
        '''
        function_context = {
            'snaplen_context': {'friendly_name': 'Snaplen context mismatch', 'category': 'D'},
            'file_and_data_size': {'friendly_name': 'File and data size mismatch', 'category': 'D'},
            'mismatched_checksums': {'friendly_name': 'Mismatched checksums', 'category': 'A'},
            'mismatched_protocols': {'friendly_name': 'Mismatched protocols', 'category': 'A'},
            'incorrect_packet_length': {'friendly_name': 'Incorrect packet length', 'category': 'C'},
            'invalid_packet_payload': {'friendly_name': 'Invalid packet payload', 'category': 'B'},
            'insuficient_capture_length': {'friendly_name': 'Insuficient capture length', 'category': 'C'},
            'mismatched_ntp_timestamp': {'friendly_name': 'Mismatched NTP timestamp', 'category': 'C'},
            'missing_arp_traffic': {'friendly_name': 'Missing ARP traffic', 'category': 'C'},
            'inconsistent_mac_maps': {'friendly_name': 'Inconsistent MAC maps', 'category': 'A'},
            'lost_arp_traffic': {'friendly_name': 'Lost ARP traffic', 'category': 'A'},
            'missing_arp_responses': {'friendly_name': 'Missing ARP responses', 'category': 'A'},
            'inconsistent_ttls': {'friendly_name': 'Inconsistent TTLs', 'category': 'C'},
            'inconsistent_fragmentation': {'friendly_name': 'Inconsistent fragmentation', 'category': 'A'},
            'sudden_drops_for_ip_source': {'friendly_name': 'Sudden drops for IP source', 'category': 'B'},
            'inconsistent_interpacket_gaps': {'friendly_name': 'Inconsistent interpacket gaps', 'category': 'B'},
            'incomplete_tcp_streams': {'friendly_name': 'Incomplete tcp streams', 'category': 'B'},
            'inconsistent_mss': {'friendly_name': 'Inconsistent MSS', 'category': 'C'},
            'inconsistent_window_size': {'friendly_name': 'Inconsistent window size', 'category': 'C'},
            'mismatched_ciphers': {'friendly_name': 'Mismatched ciphers', 'category': 'C'},
            'mismatched_dns_query_answer': {'friendly_name': 'Mismatched DNS query answer', 'category': 'C'},
            'mismatched_dns_answer_stack': {'friendly_name': 'Mismatched DNS answer stack', 'category': 'C'},
            'missing_translation_of_visited_domain': {'friendly_name': 'Missing translation of visited domain', 'category': 'A'},
            'translation_of_unvisited_domains': {'friendly_name': 'Translation of unvisited domains', 'category': 'B'},
            'incomplete_ftp': {'friendly_name': 'Incomplete FTP', 'category': 'B'},
            'missing_dhcp_ips': {'friendly_name': 'Missing DHCP IPs', 'category': 'C'},
            'missing_icmp_ips': {'friendly_name': 'Missing ICMP IPs', 'category': 'B'},
            'inconsistent_user_agent': {'friendly_name': 'Inconsistent user agent', 'category': 'C'},
        }

        return function_context
    
    def get_probability(self, weighted_average):
        '''
        Transform weighted_average to the resulting probability by logistic function
        Args:
            weighted_average: weighted_average of modification

        Returns:
            resulting_probability: resulting probability of modification
        '''
        L = 100
        x_0 = 10
        k = 0.15

        resulting_probability = L / (1 + math.exp(-k * (weighted_average - x_0)))

        return round(resulting_probability, 2)
    
    def get_weighted_average(self):
        '''
        Calculate probability of modification
        Args:

        Returns:
            average: weighted average
        '''
        weights = {
            'A': 1,
            'B': 3,
            'C': 5,
            'D': 20,
        }
        total_weight = 0
        probability = 0.00

        for key, value in self.pcap_modifications.items():
            probability += int(value) * weights[self.function_context[key]['category']]
            total_weight += weights[self.function_context[key]['category']]

        for key, value in self.packet_modifications.items():
            if type(value) is dict:
                if value['total'] == 0:
                    continue
                probability += (value['failed'] / value['total']) * weights[self.function_context[key]['category']]
            else:
                if not self.misc_tests:
                    continue 
                probability += (value / self.packet_count) * weights[self.function_context[key]['category']]

            total_weight += weights[self.function_context[key]['category']]

        avg = (probability / total_weight) * 100
        return round(avg, 2)

    def print_results(self):
        '''
        Print results of the modification detection
        Args:

        Returns:
        '''
        pcap_keys = self.pcap_modifications.keys()
        packet_keys = self.packet_modifications.keys()

        print ("")
        print ("=== Results === " + self.pcap_path)
        print ("")

        print("Pcap modifications:")
        for key in pcap_keys:
            if self.pcap_modifications[key]:
                print (self.function_context[key]['friendly_name'], " = ", "Modified")
            else:
                print (self.function_context[key]['friendly_name'], " = ", "Not modified")

        print ("")

        print("Packet modifications:")
        for key in packet_keys:
            if type(self.packet_modifications[key]) is dict:
                print (self.function_context[key]['friendly_name'], " = ", str(self.packet_modifications[key]['failed']) + "/" + str(self.packet_modifications[key]['total']))
            else:
                print (self.function_context[key]['friendly_name'], " = ", str(self.packet_modifications[key]) + "/" + str(self.packet_count))

        print ("")
        print ("Probability of modification: " + str(self.probability) + "%")
        print ("Total time: " + str(self.time))
        print ("")

    def log_results_to_file(self):
        '''
        Log results of the modification detection to a file
        Args:

        Returns:
        '''
        pcap_keys = self.pcap_modifications.keys()
        packet_keys = self.packet_modifications.keys()

        with open('log.log', 'a') as f:
            f.write("=== Results === " + self.pcap_path + "\n\n")

            f.write("Pcap modifications:\n")
            for key in pcap_keys:
                if self.pcap_modifications[key]:
                    f.write(self.function_context[key]['friendly_name'] + " = " + "Modified\n")
                else:
                    f.write(self.function_context[key]['friendly_name'] + " = " + "Not modified\n")

            f.write("\n")

            f.write("Packet modifications:\n")
            for key in packet_keys:
                if type(self.packet_modifications[key]) is dict:
                    f.write(self.function_context[key]['friendly_name'] + " = " + str(self.packet_modifications[key]['failed']) + "/" + str(self.packet_modifications[key]['total']) + "\n")
                else:
                    f.write(self.function_context[key]['friendly_name'] + " = " + str(self.packet_modifications[key]) + "/" + str(self.packet_count) + "\n")

            f.write("\n")
            f.write("Probability of modification: " + str(self.probability) + "%\n")
            f.write("Total time: " + str(self.time) + "\n\n")

    def generate_results_summary_file(self):
        '''
        Generate summary file with results of the modification detection
        Args:

        Returns:
        '''
        html = ET.Element('html')
        head = ET.Element('head')
        body = ET.Element('body')
        html.append(head)
        html.append(body)

        title = ET.Element('title')
        title.text = "Results of the modification detection for the pcap file: " + self.pcap_path
        style = ET.Element('style')
        style.text =  \
            """
            body {
                font-family: Arial, Helvetica, sans-serif;
                margin: 0 auto;
            }
            .container {
                display: flex;
                flex-wrap: wrap;
                justify-content: space-between;
                padding: 20px;
            }

            h1 {
                text-align: center;
            }
            
            .col {
                flex: 0 0 33%;
                border: 1px solid #ccc;
                border-radius: 5px;
            }

            .col h2 {
                text-align: center;
            }

            .col h3 {
                padding: 0 20px;
            }
            
            table {
                border-collapse: collapse;
                width: 100%;
            }
            
            th, td {
                text-align: left;
                padding: 8px;
                border-bottom: 1px solid #ddd;
            }
            
            th {
                background-color: #f2f2f2;
            }

            .low{
                color: #097e18;
            }
            .medium{
                color: #ffc505;
            }
            .high{
                color: #ff3131;
            }
            """
        head.append(title)
        head.append(style)

        h1 = ET.Element('h1')
        h1.text = "Results of the modification detection for the pcap file: " + self.pcap_path
        body.append(h1)

        container = ET.Element('div')
        container.set('class', 'container')
        body.append(container)

        col1 = ET.Element('div')
        col1.set('class', 'col')
        container.append(col1)
        col2 = ET.Element('div')
        col2.set('class', 'col')
        container.append(col2)
        col3 = ET.Element('div')
        col3.set('class', 'col')
        container.append(col3)
        

        h2 = ET.Element('h2')
        h2.text = "Pcap modifications"
        col1.append(h2)

        h2 = ET.Element('h2')
        h2.text = "Packet modifications"
        col2.append(h2)

        h2 = ET.Element('h2')
        h2.text = "Summary"
        col3.append(h2)

        table1 = ET.Element('table')
        tr = ET.Element('tr')
        table1.append(tr)
        th = ET.Element('th')
        th.text = "Modification"
        tr.append(th)
        th = ET.Element('th')
        th.text = "Result"
        tr.append(th)
        col1.append(table1)

        table2 = ET.Element('table')
        tr = ET.Element('tr')
        table2.append(tr)
        th = ET.Element('th')
        th.text = "Modification"
        tr.append(th)
        th = ET.Element('th')
        th.text = "Result"
        tr.append(th)
        col2.append(table2)

        table3 = ET.Element('table')
        tr = ET.Element('tr')
        table3.append(tr)
        th = ET.Element('th')
        th.text = "Property"
        tr.append(th)
        th = ET.Element('th')
        th.text = "Value"
        tr.append(th)
        col3.append(table3)


        pcap_keys = self.pcap_modifications.keys()
        for key in pcap_keys:
            tr = ET.Element('tr')
            table1.append(tr)

            td = ET.Element('td')
            td.text = self.function_context[key]['friendly_name']
            tr.append(td)

            td = ET.Element('td')
            if self.pcap_modifications[key]:
                td.text = "Modified"
            else:
                td.text = "Not modified"
            tr.append(td)

        packet_keys = self.packet_modifications.keys()
        for key in packet_keys:
            tr = ET.Element('tr')
            table2.append(tr)

            td = ET.Element('td')
            td.text = self.function_context[key]['friendly_name']
            tr.append(td)

            td = ET.Element('td')
            if type(self.packet_modifications[key]) is dict:
                td.text = str(self.packet_modifications[key]['failed']) + "/" + str(self.packet_modifications[key]['total'])
            else:
                td.text = str(self.packet_modifications[key]) + "/" + str(self.packet_count)
            tr.append(td)

        tr = ET.Element('tr')
        table3.append(tr)
        td = ET.Element('td')
        td.text = "Processed packets"
        tr.append(td)
        td = ET.Element('td')
        td.text = str(self.packet_count)
        tr.append(td)

        tr = ET.Element('tr')
        table3.append(tr)
        td = ET.Element('td')
        td.text = "Total time"
        tr.append(td)
        td = ET.Element('td')
        td.text = self.time
        tr.append(td)

        prob = 'low'
        if self.probability > 25 and self.probability < 75:
            prob = 'medium'
        elif self.probability >= 75:
            prob = 'high'

        h3 = ET.Element('h3')
        h3.text = "Modification probability: "
        span = ET.Element('span')
        span.set('class', prob)
        span.text = str(self.probability) + "%"
        h3.append(span)
        col3.append(h3)

        tree = ET.ElementTree(html)

        filename = self.pcap_path + "___result.html"
        filename = filename.replace('/', '_').replace('\\', '_').replace(':', '_').replace('*', '_').replace('?', '_')

        with open(filename, "wb") as fh:
            tree.write(fh)
