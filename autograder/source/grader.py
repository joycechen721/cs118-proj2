import json
import os
import sys
import tests

def run_transfer_tests():
    instances = [
        tests.TransferTest('ASCII transfer (self)', 5, 'ascii_cli.txt', 'ascii_server.txt', visible=True),
        tests.TransferTest('Binary transfer (self)', 5, 'small_1.bin', 'small_2.bin', visible=True),

        tests.TransferTest('Binary transfer (client->reference server)', 5, 'small_1.bin', 'small_2.bin', visible=True, use_reference_server=True),
        tests.TransferTest('Binary transfer (reference client->server)', 5, 'small_1.bin', 'small_2.bin', visible=True, use_reference_client=True),

        tests.TransferTest('Binary transfer (client->reference server, losses)', 5, 'small_1.bin', 'small_2.bin', visible=True, use_reference_server=True, proxy_loss=0.1, test_time=15),
        tests.TransferTest('Binary transfer (reference client->server, losses)', 5, 'small_1.bin', 'small_2.bin', visible=True, use_reference_client=True, proxy_loss=0.1, test_time=15),

        tests.TransferTest('Binary transfer (client->reference server, packet reordering)', 5, 'small_1.bin', 'small_2.bin', visible=True, use_reference_server=True, proxy_reorder=1.0, test_time=15),
        tests.TransferTest('Binary transfer (reference client->server, packet reordering)', 5, 'small_1.bin', 'small_2.bin', visible=True, use_reference_client=True, proxy_reorder=1.0, test_time=15),

        tests.TransferTest('Large file transfer (client->reference server)', 5, 'large.bin', 'small_2.bin', visible=True, test_time=10, use_reference_server=True),
        tests.TransferTest('Large file transfer (reference client->server)', 5, 'large.bin', 'small_2.bin', visible=True, test_time=10, use_reference_client=True),

        tests.TransferTest('Encrypt-then-MAC (reference client->server)', 10, 'small_1.bin', 'small_2.bin', visible=True, security=True, use_reference_client=True, security_mac=True),

        tests.TransferTest('Secure binary transfer (reference client->server)', 15, 'small_1.bin', 'small_2.bin', visible=True, security=True, use_reference_client=True),
        tests.TransferTest('Secure binary transfer (client->reference server)', 15, 'small_1.bin', 'small_2.bin', visible=True, security=True, use_reference_server=True),
    ]
    for instance in instances:
        instance.run()

    if instances[-1].get_result().get('score', 0) > 0:
        failing_tests = [
            tests.TransferTest('Server certificate validation (client->reference server)', 5, 'small_1.bin', 'small_2.bin', visible=True, security=True, use_reference_server=True, ca_pub_key='other/ca_pub_key_2.bin', should_fail=True),
            tests.TransferTest('Server key verification (client->reference server)', 5, 'small_1.bin', 'small_2.bin', visible=True, security=True, use_reference_server=True, server_priv_key='other/priv_key_2.bin', should_fail=True),
        ]
        for instance in failing_tests:
            instance.run()
        instances.extend(failing_tests)

    return [x.get_result() for x in instances]

def main():
    result = []

    # Compilation
    make = tests.CompileTest()
    make.run()
    result.append(make.get_result())

    # Actual tests
    if (make.success):
        result.extend(run_transfer_tests())

    pts = sum(x.get('score', 0) for x in result)
    print(f'{pts}/100')

    summary_workaround = {
        'name': f'Total points: {pts}/100',
        'status': 'passed',
        'visibility': 'visible',
    }
    result.append(summary_workaround)

    data = {
        'tests': result,
        'score': pts,
        'visibility': 'visible',
    }
    if (os.environ.get('PROD', False)):
        with open(f'/autograder/results/results.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    else:
        print(json.dumps(data, indent=4))

if __name__ == '__main__':
    main()