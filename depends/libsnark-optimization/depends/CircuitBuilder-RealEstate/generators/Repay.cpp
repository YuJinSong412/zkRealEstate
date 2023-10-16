/*******************************************************************************
 * Authors: Yujin Song
 * 			Thomas Haywood
 *******************************************************************************/

#include <limits>

#include <api.hpp>
#include <global.hpp>
#include <BigInteger.hpp>
#include <Instruction.hpp>
#include <Wire.hpp>
#include <WireArray.hpp>
#include <BitWire.hpp>
#include <ConstantWire.hpp>
#include <LinearCombinationBitWire.hpp>
#include <LinearCombinationWire.hpp>
#include <VariableBitWire.hpp>
#include <VariableWire.hpp>
#include <WireLabelInstruction.hpp>

#include <BasicOp.hpp>
#include <MulBasicOp.hpp>
#include <AssertBasicOp.hpp>

#include <Exceptions.hpp>
#include <CircuitGenerator.hpp>
#include <CircuitEvaluator.hpp>

#include "Repay.hpp"
#include "../Gadgets/BondDecryptionGadget.hpp"
#include <HashGadget.hpp>
#include <MerkleTreePathGadget.hpp>
#include <ECGroupOperationGadget.hpp>
#include <ECGroupGeneratorGadget.hpp>

#include <logging.hpp>
#include <DecryptionGadget.hpp>

using namespace CircuitBuilder::Gadgets;

namespace CircuitBuilder
{
    namespace RealEstate
    {

        Repay::Repay(string circuitName, int __treeHeight, const BigInteger &__G1_GENERATOR, Config &config)
            : CircuitBuilder::CircuitGenerator(circuitName, config),
              treeHeight(__treeHeight),
              G1_GENERATOR(__G1_GENERATOR)
        {
        }

        void Repay::buildCircuit()
        {

            /* statements */
            CT_bond_balance = createInputWire("CT_bond_balance");
            cnt = createInputWire("cnt");
            old_CT_bond_balance = createInputWire("old_CT_bond_balance");
            PK_own_creditor = createInputWire("PK_own_creditor");
            C_v_creditor = createInputWire("C_v_creditor");

            c_0_creditorPKE = createInputWire("c_0_creditorPKE");
            c_1_creditorPKE = createInputWire("c_1_creditorPKE");
            G = createInputWire("G");

            CT_v_creditor = createInputWire("CT_v_creditor");

            CT_table = createInputWire("CT_table");



            /* witnesses */
            value_old_debtor = createProverWitnessWire("value_old_debtor");
            value_new_creditor = createProverWitnessWire("value_new_creditor");
            value_new_debtor = createProverWitnessWire("value_new_debtor");
            k_msg = createProverWitnessWire("k_msg");
            CT_r_ = createProverWitnessWire("CT_r_");
            CT_r = createProverWitnessWire("CT_r");
            old_bond_balance = createProverWitnessWire("old_bond_balance");


            table_balance = createProverWitnessWireArray(tableBalanceLength, "table_balance");
            bond_balance = createProverWitnessWire("bond_balance");

            r_C_v_creditor = createProverWitnessWire("r_C_v_creditor");
            k = createProverWitnessWire("k");

            PK_enc_creditor = createProverWitnessWire("PK_enc_creditor");

            ENA_debtor = createProverWitnessWire("ENA_debtor");
            ENA_creditor = createProverWitnessWire("ENA_creditor");
            old_ENA_debtor = createProverWitnessWire("old_ENA_debtor");

            r_update_bond_balance = createProverWitnessWire("r_update_bond_balance");
            r = createProverWitnessWire("r");


            vector<WirePtr> nextInputWires;
            HashGadget *hashGadget;

            //v' = v+ v'' (이전 ENA 잔고(value_old_debtor), 채무자가 돈 보낸 후 ENA 잔고(value_new_debtor), 채무자가 채권자한테 보내야할 돈(value_new_creditor))
            WirePtr v_eval = value_new_debtor->add(value_new_creditor);
            addEqualityAssertion(value_old_debtor, v_eval, "invalid value_old_debtor");


            // old_bond_balance = SKE.Dec(k_msg, old_CT_bond_balance) -> 이전
            DecryptionGadget *decGadget2 = allocate<DecryptionGadget>(this, *old_CT_bond_balance, k_msg);
            WirePtr bond_balance_old = decGadget2->getOutputWires()[0];

            //bond_balance = bond_balance - v'' (update = old - 채권자한테 보내야할 돈)
            WirePtr result = bond_balance_old->sub(value_new_creditor);
            addEqualityAssertion(result, bond_balance, "bond_balance_update not equal result");

            //CT_bond_balance = SKE.Enc(k_msg, bond_balance) : 업데이트가 잘 되었는지 
            nextInputWires = {k, r_update_bond_balance};
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(bond_balance->add(hashGadget->getOutputWires()[0]),CT_bond_balance, "invalid CT");


            // // bond_balance = SKE.Dec(k_msg, CT_bond_balance) -> 업데이트된
            // DecryptionGadget *decGadget = allocate<DecryptionGadget>(this, *CT_bond_balance, k);
            // WirePtr bond_balance_update = decGadget->getOutputWires()[0];

            //돈 보내는 부분
            //C_v_creditor = H(PK_own_creditor,r_C_v_creditor, value_new_creditor)
            nextInputWires = {PK_own_creditor, r_C_v_creditor, value_new_creditor}; //concat
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(hashGadget->getOutputWires()[0], C_v_creditor, "C_v_creditor not equal");


            //CT_v_creditor = PKE.Enc(PK_enc_creditor, (PK_own_creditor,r_C_v_creditor, value_new_creditor))
            // ECGroupGeneratorGadget *ecGadget = allocate<ECGroupGeneratorGadget>(this, G, r_creditorPKE);
            // addEqualityAssertion(ecGadget->getOutputWires()[0], c_0_creditorPKE, "c_0 not equal");
            
            ECGroupGeneratorGadget *ecGadget = allocate<ECGroupGeneratorGadget>(this, PK_enc_creditor, r);
            addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), c_1_creditorPKE, "c_1' not equal");

            WirePtr CT_temp;
            vector<WirePtr> temp = {PK_own_creditor, r_C_v_creditor, value_new_debtor}; 
            for(int i = 0; i<3;i++){
                hashGadget = allocate<HashGadget>(this, k->add(i));
                CT_temp = temp[i]->add(hashGadget->getOutputWires()[0]);
                addEqualityAssertion(CT_v_creditor, CT_temp, "CT_v_creditor is not equal");
            }


            //ENA_debtor = SKE.Enc(k_msg, value_new_debtor)
            nextInputWires = {k_msg, CT_r};
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(value_new_debtor->add(hashGadget->getOutputWires()[0]),ENA_debtor, "invalid CT");

            //old_ENA_debtor = SKE.Enc(k_msg, value_old_debtor)
            nextInputWires = {k_msg, CT_r_};
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(value_old_debtor->add(hashGadget->getOutputWires()[0]),old_ENA_debtor, "invalid CT");

            //CT_table = H(table_balance)
            //CT_table = H(table_balance) -> array...
            for(int i = 0 ; i < tableBalanceLength ; i++){
                nextInputWires.push_back(table_balance->get(i));
            }
            
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(hashGadget->getOutputWires()[0], CT_table, "CT_table != H(table_balance)");


            // bond_balance_update = table[cnt]
            BigInteger cntBigInteger = ((ConstantWire*) cnt)->getConstant();
            string cntString = cntBigInteger.toString();
           // stol(cntString)
            addEqualityAssertion(table_balance->get(stol(cntString)), bond_balance,"bond_balance_update != table[cnt]");
            
          


            return;
        }

        void Repay::finalize()
        {
            // CT_userKey, CT_bankKey, CT_bond, CT_bond_balance, PK_bank, PK_user
            // if (CT_userKey)
            // {
            //     delete CT_userKey;
            // }
            // if (CT_bankKey)
            // {
            //     delete CT_bankKey;
            // }
            // if (CT_bond)
            // {
            //     delete CT_bond;
            // }
            // if (CT_bond_balance)
            // {
            //     delete CT_bond_balance;
            // }
            // if (PK_bank)
            // {
            //     delete PK_bank;
            // }
            // if (PK_user)
            // {
            //     delete PK_user;
            // }
            // if (intermediateHashWires)
            // {
            //     delete intermediateHashWires;
            // }
            CircuitGenerator::finalize();
        }

        void Repay::assignInputs(CircuitEvaluator &circuitEvaluator)
        {
            assign_inputs(circuitEvaluator);
            return;
        }

    }
}

namespace libsnark
{
    // circuit setup
    CircuitGenerator *create_crv_real_estate_generator(const CircuitArguments &circuit_arguments, const Config &__config)
    {
        string hashType = "MiMC7";
        const string treeHeightKey = "treeHeight";
        int treeHeight = 0;
        const string hashTypeKey = "hashType";

        if (circuit_arguments.find(treeHeightKey) != circuit_arguments.end())
        {
            treeHeight = atoi(circuit_arguments.at(treeHeightKey).c_str());
        }

        if (circuit_arguments.find(hashTypeKey) != circuit_arguments.end())
        {
            hashType = circuit_arguments.at(hashTypeKey);
        }

        if (treeHeight != 8 && treeHeight != 16 && treeHeight != 32 && treeHeight != 64)
        {
            LOGD("\n\n");
            LOGD("CreateGenerator     :\n");
            LOGD("Invalid tree height : %d\n", treeHeight);
            LOGD("Only support 8, 16, 32, 64 \n");
            return NULL;
        }

        if (hashType.compare("MiMC7") != 0 && hashType.compare("SHA256") != 0 && hashType.compare("Poseidon") != 0)
        {
            LOGD("\n\n");
            LOGD("CreateGenerator   :\n");
            LOGD("Invalid hash type : %s\n", hashType.c_str());
            LOGD("Only support MiMC7, SHA256, Poseidon \n");
            return NULL;
        }

        Config config = __config;

        BigInteger G1_GENERATOR = 0l;
        if (config.EC_Selection == EC_BLS12_381)
        {
            G1_GENERATOR = BigInteger("67c5b5fed18254e8acb66c1e38f33ee0975ae6876f9c5266a883f4604024b3b8", 16);
        }
        else if (config.EC_Selection == EC_ALT_BN128)
        {
            G1_GENERATOR = BigInteger("16FD271AE0AD87DDAE03044AC6852EE1D2AC024D42CFF099C50EA7510D2A70A5", 16);
        }

        config.evaluationQueue_size = 53560;
        config.inWires_size = 20;
        config.outWires_size = 0;
        config.proverWitnessWires_size = 2080;
        config.hashType = hashType;

        auto generator = new CircuitBuilder::RealEstate::Repay("RealEstate", treeHeight, G1_GENERATOR, config);
        generator->generateCircuit();

        return generator;
    }

}