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

	class Repay : public CircuitBuilder::CircuitGenerator {
	
	private:


		/********************* INPUT ***************************/

		WirePtr CT_bond_balance, old_CT_bond_balance, cnt;

		WirePtr PK_own_creditor;
		WirePtr C_v_creditor; //azeroth에서 cm

		WirePtr c_0_creditorPKE, c_1_creditorPKE, G;
		WirePtr CT_v_creditor;

		WirePtr CT_table;

		/********************* Witness ***************************/
        WirePtr value_old_debtor, value_new_creditor, value_new_debtor;//debtor의 이전 ENA 잔고, 보내야할 돈, 돈 보낸후 ENA잔고

        WirePtr  k_msg, r_update_bond_balance, bond_balance, old_bond_balance, k;

		WiresPtr table_balance;

		WirePtr r_C_v_creditor, r, CT_r_, CT_r;
		WirePtr r_creditorPKE, PK_enc_creditor;

		WirePtr ENA_debtor, ENA_creditor, old_ENA_debtor; // , 업데이트된 sct, 이전 sct
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
        // WirePtr id_bond, CT_debtorKey, CT_creditorKey, CT_bond_balance;
		

		// /********************* Witness ***************************/
        
        // WirePtr CT_r_, bond_balance, k_msg;


		// /********************* MerkleTree ***************************/
		// WirePtr directionSelector;
		// WiresPtr intermediateHashWires;
		// static const int PKECipherLength = 3;
		// static const int SECipherLength = 2;
		// static const int pkLength = 3;
		// int treeHeight;
		// BigInteger G1_GENERATOR;

		// static const int bondDataLength = 14;

	protected:

		void buildCircuit() ;

		void finalize();

	public: 

		Repay(string circuitName, int treeHeight , const BigInteger & G1_GENERATOR , Config &config) ;
		
		void assignInputs(CircuitEvaluator &evaluator) ;

	};

}}