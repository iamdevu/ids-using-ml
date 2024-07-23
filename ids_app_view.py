import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

import pydivert
from joblib import load
from pandas import DataFrame
from scapy.all import *
import sys
import pandas as pd


def process_packet(packet, preprocess, model, features, xgboost, cols=None):
    pkt = []
    l3 = IP(bytes(packet.raw))
    l4 = TCP(bytes(packet.raw))

    pkt.append(l3.id)    # ip_id
    pkt.append(l3.flags.DF & 1)  # ip_flag_df
    pkt.append(l3.ttl)   # ip_ttl
    pkt.append(l3.len)   # ip_len
    pkt.append(l3.tos)     # ip_dsfield

    pkt.append(l4.sport) # tcp_dport
    pkt.append(l4.seq)   # tcp_seq
    pkt.append(len(l4.payload))  # tcp_len
    pkt.append(len(l4))  # tcp_hdr_len

    # bitwise operation on the flags to retrieve the value
    pkt.append(l4.flags.F & 1)   # tcp_flag_fin
    pkt.append(l4.flags.S & 1)   # tcp_flag_syn
    pkt.append(l4.flags.R & 1)   # tcp_flag_rst
    pkt.append(l4.flags.P & 1)   # tcp_flag_push
    pkt.append(l4.flags.A & 1)   # tcp_flag_ack
    pkt.append(l4.flags.U & 1)   # tcp_flag_urg
    pkt.append(l4.flags.C & 1)   # tcp_flag_cwr
    pkt.append(l4.window)        # tcp_window_size
    pkt.append(l4.urgptr)        # tcp_urgent_pointer
    
    # to retrieve mss_val inside field TCP options
    # normally this field is in the byte format, so the conversion to int from bytes is required
    # if the field MSS is not set, the value is used as zero
    pkt.append(next((int.from_bytes(x[1], byteorder=sys.byteorder) for x in l4.options if x[0] == "MSS"), 0)) # tcp_options_mss_val
    
    df = DataFrame([pkt], columns=features)

    # if xgboost == 1:
        # df = df[cols]

    X = preprocess.transform(df)
    # the pre-processing transform pandas dataframe to numpy array
    # to make XGBoost work it is required to get back to dataframe format
    X = DataFrame(X, columns=features)
        
    predict = model.predict(X)
        

    if predict == 0:    # the model predicts the packet as bonafide
        return True
    else:               # the model predicts the packet as an attack
        return False







def main(ids_host_ip):
    print('[LISTENING]:', ids_host_ip)
    accept_model = ('knn', 'rf', 'dt', 'lr', 'xgb', 'nb', 'svm', 'mlp')
    
    if len(sys.argv)<2 or (len(sys.argv)==2 and sys.argv[1] in ('-h', '--help')):
        print("=========================")
        print("[USAGE]: {0} <model_name>".format(sys.argv[0]))
        print("Available models: knn, rf, dt, lr, xgb, nb, svm, mlp")
        
        return

    elif len(sys.argv)==2 and sys.argv[1] in accept_model:
        model_name = sys.argv[1] + ".pkl"
        print("[USING]: model", model_name)
            
        
    else:
        print("[ERROR] wrong model supplied")
        return
        
        
    preprocess = load(open("saved_whole/scaler.pkl", "rb"))
    model = load(open("saved_whole/" + model_name, "rb"))


####################################
    # try:
        # cols = model.get_booster().feature_names
        # xgboost = 1
    # except:
        # not a xgboost model
        # xgboost = 0
        # cols=None
#########################################
    
    features = ['ip.id', 'ip.flags.df', 'ip.ttl', 'ip.len',
           'ip.dsfield', 'tcp.srcport', 'tcp.seq', 'tcp.len', 'tcp.hdr_len',
           'tcp.flags.fin', 'tcp.flags.syn', 'tcp.flags.reset',
           'tcp.flags.push', 'tcp.flags.ack', 'tcp.flags.urg',
           'tcp.flags.cwr', 'tcp.window_size', 'tcp.urgent_pointer',
           'tcp.options.mss_val']

##########################################

    try:    
        # works fine
        w = pydivert.WinDivert(f"inbound and ip.DstAddr={ids_host_ip} and tcp and tcp.PayloadLength > 0")
        w.open()
        
    except OSError as e:
        print(f"Access denied or other error occurred: {e}")
        print("Do I have administrative rights?")
        sys.exit(-1)

    
 ########################################
 
    try:
        for packet in w:
            xgboost = cols = 0
            if process_packet(packet, preprocess, model, features, xgboost, cols):
                w.send(packet)
                print('bonafide')
        
            else:
                # w.drop() does not exist as doing nothing drops the packet
                print('probe attack')
            
            
    except KeyboardInterrupt:
        print('User Interrupt... Exitting gracefully')
        
    except Exception as e:
        print("error:", e)
        
    finally:
        print('Cleaning up...')
        w.close()
        sys.exit(-1)
    
        

#############################
if __name__ == "__main__":
# capture packets destined to 192.168.56.1 only 
    main(ids_host_ip="192.168.56.1")
