/*******************************************************************************
 * Authors: Yujin Song
 * 			Thomas Haywood
 *******************************************************************************/

 
#pragma once


#include <global.hpp>
#include <Config.hpp>
#include <CircuitGenerator.hpp>


namespace CircuitBuilder {
namespace RealEstate {

	class AcceptLending : public CircuitBuilder::CircuitGenerator {
	
	private:

		/********************* INPUT ***************************/
        WiresPtr CT_bondData;
		WirePtr CT_bond_balance, id_bond, CT_creditorKey;
		
		WirePtr CT_table;

		WirePtr c_0_creditorPKE, c_1_creditorPKE, G;
		WirePtr c_0, c_1;
		
		WirePtr C_v_debtor; //azeroth에서 cm
		WirePtr PK_own_debtor;
		WirePtr CT_v_debtor;

		/********************* Witness ***************************/
        WirePtr bond_balance, index, PK_enc_creditor, PK_enc_debtor;
		WirePtr ENA_debtor, ENA_creditor, old_ENA_creditor; // , 업데이트된 sct, 이전 sct
		WirePtr value_old_creditor, value_new_debtor, value_new_creditor;//이전 ENA 잔고, 보내야할 돈, 돈 보낸후 ENA잔고
		WiresPtr bond_data;
		
		WiresPtr table_balance;

		WirePtr k, k_ENA_creditor;

		WirePtr r_C_v_debtor, r;
		WirePtr CT_r, CT_r_;

		/********************* MerkleTree ***************************/
		WirePtr directionSelector;
		WiresPtr intermediateHashWires;
		static const int CTLength = 3;
		static const int ctLength = 2;
		static const int pkLength = 3;
		int treeHeight;
		BigInteger G1_GENERATOR;

		static const int bondDataLength = 13;

		static const int tableBalanceLength = 12; //1년으로 고정함
	
		// /********************* INPUT ***************************/
        // WiresPtr CT_bondData;
		// WirePtr CT_bond_balance, id_bond, CT_creditorKey;
		
		// WirePtr CT_table;
		
		// // WirePtr commitBankValue, commitUserNewValue, commitBankNewValue, nf;
		// // WiresPtr CT_userKey, CT_bankKey, CT_bond, CT_bond_balance, PK_bank, CT_userMoney, CT_bankMoney;
        // // WirePtr id_bond, LoanPeriod, RetentionPeriod;

		// /********************* Witness ***************************/
        // WirePtr  k_msg, bond_balance, index, value_creditor;
		// WiresPtr bond_data;
		
		// WiresPtr table_balance;

		
		// // WirePtr r, value_bank, value_new_user, value_new_bank, data_balance, SK_user, SK_bank, k ;
        // // WiresPtr PK_user;

		// /********************* MerkleTree ***************************/
		// WirePtr directionSelector;
		// WiresPtr intermediateHashWires;
		// static const int PKECipherLength = 3;
		// static const int SECipherLength = 2;
		// static const int pkLength = 3;
		// int treeHeight;
		// BigInteger G1_GENERATOR;

		// static const int bondDataLength = 13;

		// static const int tableBalanceLength = 12; //1년으로 고정함

	protected:

		void buildCircuit() ;

		void finalize();

	public: 

		AcceptLending(string circuitName, int treeHeight , const BigInteger & G1_GENERATOR , Config &config) ;
		
		void assignInputs(CircuitEvaluator &evaluator) ;

	};

}}