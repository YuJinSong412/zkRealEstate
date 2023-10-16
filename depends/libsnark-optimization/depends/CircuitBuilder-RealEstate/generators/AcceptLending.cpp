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

#include "AcceptLending.hpp"
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

        AcceptLending::AcceptLending(string circuitName, int __treeHeight, const BigInteger &__G1_GENERATOR, Config &config)
            : CircuitBuilder::CircuitGenerator(circuitName, config),
              treeHeight(__treeHeight),
              G1_GENERATOR(__G1_GENERATOR)
        {
        }

        void AcceptLending::buildCircuit()
        {

            /* statements */
            CT_bondData = createInputWireArray(13, "CT_bondData");
            
            CT_bond_balance = createInputWire("CT_bond_balance");
            id_bond = createInputWire("id_bond");
            CT_creditorKey = createInputWire("CT_creditorKey");

            CT_table = createInputWire("CT_table");

            c_0 = createInputWire("c_0");
            c_1 = createInputWire("c_1");

            c_0_creditorPKE = createInputWire("c_0_creditorPKE");
            c_1_creditorPKE = createInputWire("c_1_creditorPKE");
            G = createInputWire("G");

            C_v_debtor = createInputWire("C_v_debtor");
            PK_own_debtor = createInputWire("PK_own_debtor");
            CT_v_debtor = createInputWire("CT_v_debtor");

            /*witnesses */
            //k_msg = createProverWitnessWire("k_msg");
            bond_balance = createProverWitnessWire("bond_balance");
            index = createProverWitnessWire("index");
            PK_enc_creditor = createProverWitnessWire("PK_enc_creditor");
            PK_enc_debtor = createProverWitnessWire("PK_enc_debtor");

            ENA_debtor = createProverWitnessWire("ENA_debtor");
            ENA_creditor = createProverWitnessWire("ENA_creditor");
            old_ENA_creditor = createProverWitnessWire("old_ENA_creditor");

            value_old_creditor = createProverWitnessWire("value_old_creditor");//, 이전 ENA 잔고
            value_new_debtor = createProverWitnessWire("value_new_debtor");// 채권자가 채무자한테 보내야할 돈
            value_new_creditor = createProverWitnessWire("value_new_creditor");//채권자가 돈 보낸 후 ENA 잔고


            bond_data = createProverWitnessWireArray(bondDataLength, "bond_data"); // : 13
            table_balance = createProverWitnessWireArray(tableBalanceLength, "table_balance");
            
            //r_creditorPKE = createProverWitnessWire("r_creditorPKE");
            k = createProverWitnessWire("k");
            k_ENA_creditor = createProverWitnessWire("k_ENA_creditor");

            r_C_v_debtor = createProverWitnessWire("r_C_v_debtor");
            r = createProverWitnessWire("r");
            CT_r = createProverWitnessWire("CT_r"); // ENA_creditor
            CT_r_ = createProverWitnessWire("CT_r_"); //ENA_debtor



            vector<WirePtr> nextInputWires;
            HashGadget *hashGadget;

            // //id_bond = H(ENA_creditor, ENA_debtor, index)
            // nextInputWires = {ENA_debtor, ENA_creditor, index}; //concat
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], id_bond, "addr not equal");        
            

            //bond_balance = v'(value_new_debtor) : 채무자한테 줄 돈 dv_->v_priv_out
            addEqualityAssertion(bond_balance, value_new_debtor, "invalid bond_balance");


            //PKE 시작 -> pk_enc_creditor // 
            ECGroupGeneratorGadget *ecGadget1 = allocate<ECGroupGeneratorGadget>(this, PK_enc_creditor, r); //r_creditorPKE
            addEqualityAssertion(ecGadget1->getOutputWires()[0]->mul(k), c_1_creditorPKE, "c_1_creditorPKE not equal");
            // addEqualityAssertion(ecGadget1->getOutputWires()[0], c_0_creditorPKE, "c_0_creditorPKE not equal");

            // ecGadget1 = allocate<ECGroupGeneratorGadget>(this, PK_enc_creditor, r); //r_creditorPKE
            // addEqualityAssertion(ecGadget1->getOutputWires()[0]->mul(k), c_1_creditorPKE, "c_0_creditorPKE not equal");

            // //CT_k_creditor = PKE.ENC(pk_enc_creditor, k_msg)
            // hashGadget = allocate<HashGadget>(this, k);
            // addEqualityAssertion(CT_creditorKey, k_msg->add(hashGadget->getOutputWires()[0]), "ciphertext is not equal");

            //v' = v+ v'' (이전 ENA 잔고(value_old_creditor), 채권자가 돈 보낸 후 ENA 잔고(value_new_creditor),   채권자가 채무자한테 보내야할 돈(value_new_debtor))
            WirePtr v_eval = value_new_creditor->add(value_new_debtor);
            addEqualityAssertion(value_old_creditor, v_eval, "invalid v_out");

            //C_v_debtor = H(pk_own_debtor,r_C_v_debtor, value_new_debtor)
            nextInputWires = {PK_own_debtor, r_C_v_debtor, value_new_debtor}; //concat
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(hashGadget->getOutputWires()[0], C_v_debtor, "C_v_debtor not equal");

            //CT_v_debtor = PKE.Enc(PK_enc_debtor, (PK_own_debtor, r_C_v_debtor, value_new_debtor))
            // ECGroupGeneratorGadget *ecGadget = allocate<ECGroupGeneratorGadget>(this, G, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0], c_0, "c_0 not equal");
            
            // ecGadget = allocate<ECGroupGeneratorGadget>(this, PK_enc_debtor, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), c_1, "c_1' not equal");

            //CT_v_debtor = PKE.Enc(PK_enc_debtor, (PK_own_debtor, r_C_v_debtor, value_new_debtor))
            WirePtr CT_temp;
            vector<WirePtr> temp = {PK_own_debtor, r_C_v_debtor, value_new_debtor}; //PK_own_debtor 필요?
            for(int i = 0; i<3;i++){
                hashGadget = allocate<HashGadget>(this, k->add(i));
                CT_temp = temp[i]->add(hashGadget->getOutputWires()[0]);
                addEqualityAssertion(CT_v_debtor, CT_temp, "CT_v_debtor is not equal");
            }

            //ENA_creditor = SKE.Enc(k_msg, value_new_creditor)
            nextInputWires = {k_ENA_creditor, CT_r};
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(value_new_creditor->add(hashGadget->getOutputWires()[0]),ENA_creditor, "invalid CT");

            //old_ENA_creditor = SKE.Enc(k_msg, value_old_creditor)
            nextInputWires = {k_ENA_creditor, CT_r_};
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(value_old_creditor->add(hashGadget->getOutputWires()[0]),old_ENA_creditor, "invalid CT");


            // assert value_old_creditor >= 0
            addOneAssertion(value_old_creditor->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "value_old_creditor less than 0");

            // assert value_new_debtor >= 0
            addOneAssertion(value_new_debtor->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "value_new_debtor less than 0");

            // //CT_table = H(table_balance) -> array...
            // for(int i = 0 ; i < tableBalanceLength ; i++){
            //     nextInputWires.push_back(table_balance->get(i));
            // }
            
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], CT_table, "CT_table != H(table_balance)");

            //기존에 있던 DecryptionGadget 활용 X -> Length = 2 일때만 활용 가능
            // // bond_balance = SKE.Dec(k_msg, CT_bond_balance)
            // DecryptionGadget *decGadget3 = allocate<DecryptionGadget>(this, *CT_bond_balance, k_msg);
            // WirePtr temp_bond_balance = decGadget3->getOutputWires()[0];
            // addEqualityAssertion(temp_bond_balance, bond_balance, "bond_balance not equal");

            // // bond_balance = SKE.DEC(k_msg, CT_bond_balance)
            // nextInputWires = {k_msg, CT_r};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // WirePtr plan = CT_bond_balance->sub(hashGadget->getOutputWires()[0]);
            // addEqualityAssertion(plan, bond_balance, "bond_balance not equal");


            // bond_data = SKE.Dec(k_msg, CT_bondData)
            // DecryptionGadget *decGadget4 = allocate<DecryptionGadget>(this, *CT_bondData, k_msg);
            // vector<WirePtr> bondDatas(13);
            // for(int i = 0 ; i < 13 ; i++)
            // {
            //     bondDatas.push_back(decGadget4->getOutputWires()[i]);
            // }

            // for(int i = 0 ; i < 13 ; i++)
            // {
            //     addEqualityAssertion((*bond_data)[i], bondDatas[i], "bond_data not equal");
            // }


            // // bond_data = SKE.Dec(k_msg, CT_bondData)
            // nextInputWires = {k_msg, CT_r};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // vector<WirePtr> bondDatas(13);
            // for(int i = 0 ; i < 13 ; i++)
            // {
            //     WirePtr plan = CT_bondData->get(i)->sub(hashGadget->getOutputWires()[0]);
            //     bondDatas.push_back(plan);
            // }

            // for(int i = 0 ; i < 13 ; i++)
            // {
            //     addEqualityAssertion((*bond_data)[i], bondDatas[i], "bond_data not equal");
            // }


            return;
        }

        void AcceptLending::finalize()
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

        void AcceptLending::assignInputs(CircuitEvaluator &circuitEvaluator)
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

        auto generator = new CircuitBuilder::RealEstate::AcceptLending("RealEstate", treeHeight, G1_GENERATOR, config);
        generator->generateCircuit();

        return generator;
    }

}