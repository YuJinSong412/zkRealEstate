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

	class RequestLending : public CircuitBuilder::CircuitGenerator {
	
	private:

		/********************* INPUT ***************************/
        WirePtr CT_debtorKey, CT_creditorKey, CT_bond_balance;
		WiresPtr CT_bondData;
        WirePtr id_bond;  //id_collateral
        WirePtr c_0, c_1, G, c_2;
        WirePtr CT_table;

		WirePtr c_0_creditorPKE, c_1_creditorPKE;

		/********************* Witness ***************************/
        WirePtr r,CT_r, CT_r_, k, ENA_debtor, ENA_creditor, index, bond_balance, PK_enc_debtor, PK_enc_creditor;
        WiresPtr bond_data;
        WiresPtr table_balance;

		/********************* MerkleTree ***************************/
		//WirePtr directionSelector;
		//WiresPtr intermediateHashWires;
		static const int PKECipherLength = 3;
		static const int SECipherLength = 2;
        static const int bondDataLength = 13;
		//static const int pkLength = 3;
		//int treeHeight;
		BigInteger G1_GENERATOR;

        static const int tableBalanceLength = 12; //1년으로 고정함

	protected:

		void buildCircuit() ;

		void finalize();

	public: 

		RequestLending(string circuitName, const BigInteger & G1_GENERATOR , Config &config) ;
		
		void assignInputs(CircuitEvaluator &evaluator) ;

	};

}}