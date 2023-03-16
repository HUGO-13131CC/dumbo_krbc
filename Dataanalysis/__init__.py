import csv

if __name__ == '__main__':
    header = ['batch size(TXs)',
              'total transactions(TXs)',
              'total delay(s)',
              'average delay(s/round)',
              'average throughout(TXs/s)',
              '5% longest delay(s)',
              '5% shortest delay(s)',
              '5% least throughout(TXs/s)',
              '5% largest throughout(TXs/s)']
    data_set = []
    with open('../log/consensus-node-0.log') as f:
        print('loading data...')
        data = f.readlines()
        round_throughout = []
        round_delay = []
        single_data = None
        batch_size = 0
        num_round = 0
        for line in data:
            words = line.split(' ')
            if words[0] == "./run_local_network_test.sh":
                print(f'=========\nbatch size: {words[3]}')
                batch_size = int(words[3])
                num_round = int(words[4])
            elif words[2] == "dumbo.py" and words[8] == "Delivers":
                single_data = float(words[16])
            elif words[2] == "dumbo.py" and words[6] == "ACS":
                round_delay.append(float(words[12]))
                round_throughout.append(single_data / float(words[12]))
            elif words[2] == "dumbo.py" and words[8] == "breaks":
                print(f'==========\ntotal: {words[16]}TXs, total delay: {words[10]}sec,'
                      f' average throughout: {float(words[16])/float(words[10])}TXs/sec')
                length = len(round_throughout)
                round_delay.sort()
                round_throughout.sort()
                print(f'5% longest delay: {sum(round_delay[length-6:])/6} sec, '
                      f'5% shortest delay: {sum(round_delay[:5])/6} sec')
                print(f'5% least throughout: {sum(round_throughout[:5])/6} TXs/sec, '
                      f'5% largest throughout: {sum(round_throughout[length-6:])/6} TXs/sec')
                data_set.append({
                    'batch size(TXs)': batch_size,
                    'total transactions(TXs)': float(words[16]),
                    'total delay(s)': float(words[10]),
                    'average delay(s/round)': float(words[10])/num_round,
                    'average throughout(TXs/s)': float(words[16])/float(words[10]),
                    '5% longest delay(s)': sum(round_delay[length-6:])/6,
                    '5% shortest delay(s)': sum(round_delay[:5])/6,
                    '5% least throughout(TXs/s)': sum(round_throughout[:5])/6,
                    '5% largest throughout(TXs/s)': sum(round_throughout[length-6:])/6
                })
                round_throughout = []
                round_delay = []

    print(data_set)
    with open('data_11.csv', 'a', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=header)
        writer.writeheader()
        writer.writerows(data_set)
