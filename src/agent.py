import rlp
import forta_agent
from sqlalchemy import null
from web3 import Web3
from forta_agent import Finding, FindingType, FindingSeverity

def calc_contract_address(address, nonce) -> str:
    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def detect_contract_creations(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []
    
    tx = transaction_event.transaction
    if (tx.to is null and len(tx.data) > 0):
        created_contract_address = calc_contract_address(tx.from_, tx.nonce)
        findings.append(Finding({
            'name': 'New Contract',
            'description': f'{tx.from_} created contract {created_contract_address}',
            'alert_id': 'NEW-CREATION-MONITOR',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {
                'creator': tx.from_,
                'contract': created_contract_address,
                'network': transaction_event.network,
                'tx_hash': tx.hash
            }
        }))
    return findings


def provide_handle_transaction():
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_contract_creations(transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction()


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)