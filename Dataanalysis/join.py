import csv

if __name__ == '__main__':
    ROUND = 100
    SPLIT = 5
    header = ['# RBC instances',
              'batch size',
              'total transactions(TXs)',
              'total delay(s)',
              'average delay(s/round)',
              'average throughout(TXs/s)',
              '1% longest delay(s)',
              '1% shortest delay(s)',
              '1% least throughout(TXs/s)',
              '1% largest throughout(TXs/s)']
    data_set = []
    for i in range(1, 5):
        with open(f"data_k_{i}.csv") as f:
            data = f.readlines()[1:]
            for j in range(0, 5):
                single_data = data[j*5: (j+1)*5]
                RBC_instance = single_data[0].split(",")[0]
                batch_size = single_data[0].split(",")[1]
                t_tx = single_data[0].split(",")[2]
                t_d = 0
                t_tx_ = 0
                lgt_d_set = []
                stt_d_set = []
                lst_t_set = []
                lgt_t_set = []
                for l in single_data:
                    t_d += float(l.split(",")[3])
                    t_tx_ += float(l.split(",")[5])
                    lgt_d_set.append(float(l.split(",")[6]))
                    stt_d_set.append(float(l.split(",")[7]))
                    lst_t_set.append(float(l.split(",")[8]))
                    lgt_t_set.append(float(l.split(",")[9]))
                a_d = t_d / ROUND
                a_t = t_tx_ / SPLIT
                lgt_d = max(lgt_d_set)
                stt_d = min(stt_d_set)
                lst_t = min(lst_t_set)
                lgt_t = max(lgt_t_set)
                data_set.append({
                    '# RBC instances': RBC_instance,
                    'batch size': batch_size,
                    'total transactions(TXs)': t_tx,
                    'total delay(s)': t_d,
                    'average delay(s/round)': a_d,
                    'average throughout(TXs/s)': a_t,
                    '1% longest delay(s)': lgt_d,
                    '1% shortest delay(s)': stt_d,
                    '1% least throughout(TXs/s)': lst_t,
                    '1% largest throughout(TXs/s)': lgt_t
                })

    print(data_set)
    with open(f'data_k_RBC.csv', 'a', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=header)
        writer.writeheader()
        writer.writerows(data_set)
