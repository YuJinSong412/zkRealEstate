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

#include "RequestLending.hpp"
#include "../Gadgets/BondDecryptionGadget.hpp"
#include <HashGadget.hpp>
#include <MerkleTreePathGadget.hpp>
#include <ECGroupOperationGadget.hpp>
#include <ECGroupGeneratorGadget.hpp>

#include <logging.hpp>

using namespace CircuitBuilder::Gadgets;

namespace CircuitBuilder
{
    namespace RealEstate
    {

        RequestLending::RequestLending(string circuitName, const BigInteger &__G1_GENERATOR, Config &config)
            : CircuitBuilder::CircuitGenerator(circuitName, config),
              G1_GENERATOR(__G1_GENERATOR)
        {
        }

        void RequestLending::buildCircuit()
        {
                    
            /* statements */
            CT_debtorKey = createInputWire("CT_debtorKey");     //채무자의 pk로 Enc
            CT_creditorKey = createInputWire("CT_creditorKey"); //채권자의 pk로 Enc
            CT_bondData = createInputWireArray(13, "CT_bondData");  //채권에 적혀있는 data    random을 뺌 -> CT_r
            CT_bond_balance = createInputWire("CT_bond_balance");   //채권에 적혀있는 잔금 
            

            id_bond = createInputWire("id_bond");
            //id_collateral = createInputWire("id_collateral");

            //PKE에서 필요함 
            c_0 = createInputWire("c_0");       // CT: c_0
            c_1 = createInputWire("c_1");       //     c_1 채무자
            c_2 = createInputWire("c_2");       // c_2 : 채권자

            c_0_creditorPKE = createInputWire("c_0_creditorPKE");       // CT: c_0
            c_1_creditorPKE = createInputWire("c_1_creditorPKE");       //     c_1


            CT_table = createInputWire("CT_table");

            /* witnesses */
            r = createProverWitnessWire("r");
            CT_r_ = createProverWitnessWire("CT_r_");   //CT_bond_balance에 대한 SKE때 필요한 random값
            CT_r = createProverWitnessWire("CT_r");     //CT_bondData에 대한 SKE때 필요한 random값
            k = createProverWitnessWire("k");
            ENA_debtor = createProverWitnessWire("ENA_debtor");
            ENA_creditor = createProverWitnessWire("ENA_creditor");
            index = createProverWitnessWire("index");
            bond_balance = createProverWitnessWire("bond_balance");
            PK_enc_debtor = createProverWitnessWire("PK_enc_debtor");
            PK_enc_creditor = createProverWitnessWire("PK_enc_creditor");

            bond_data = createProverWitnessWireArray(bondDataLength, "bond_data"); // : 13

            table_balance = createProverWitnessWireArray(tableBalanceLength, "table_balance");

            //r_creditorPKE = createProverWitnessWire("r_creditorPKE");
            //k_msg = createProverWitnessWire("k_msg");

            vector<WirePtr> nextInputWires;
            HashGadget *hashGadget;

            //id_bond = H(ENA_creditor, ENA_debtor, index)
            nextInputWires = {ENA_debtor, ENA_creditor, index}; //concat
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(hashGadget->getOutputWires()[0], id_bond, "addr not equal");
            
            //PKE 시작 -> PK_enc_debtor
            ECGroupGeneratorGadget *ecGadget = allocate<ECGroupGeneratorGadget>(this, G, r);
            addEqualityAssertion(ecGadget->getOutputWires()[0], c_0, "c_0 not equal");
            
            ecGadget = allocate<ECGroupGeneratorGadget>(this, PK_enc_debtor, r);
            addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), c_1, "c_1' not equal");
            
            ecGadget = allocate<ECGroupGeneratorGadget>(this, PK_enc_creditor, r);
            addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), c_2, "c_2 not equal");

            //CT_k_debtor = PKE.ENC(pk_enc_debtor, k_msg)
            // hashGadget = allocate<HashGadget>(this, k);
            // addEqualityAssertion(CT_debtorKey, k_msg->add(hashGadget->getOutputWires()[0]), "ciphertext is not equal");

            //PKE 시작 -> pk_enc_creditor
            // ECGroupGeneratorGadget *ecGadget1 = allocate<ECGroupGeneratorGadget>(this, G, r_creditorPKE);
            // addEqualityAssertion(ecGadget1->getOutputWires()[0], c_0_creditorPKE, "c_0_creditorPKE not equal");

            // ecGadget1 = allocate<ECGroupGeneratorGadget>(this, PK_enc_creditor, r_creditorPKE);
            // addEqualityAssertion(ecGadget1->getOutputWires()[0]->mul(k), c_1_creditorPKE, "c_1_creditorPKE not equal");

            //CT_k_creditor = PKE.ENC(pk_enc_creditor, k_msg)
            // hashGadget = allocate<HashGadget>(this, k);
            // addEqualityAssertion(CT_creditorKey, k_msg->add(hashGadget->getOutputWires()[0]), "ciphertext is not equal");
            
            
            //CT_bondData = SKE.Enc(k_msg, bond_data)
            WirePtr CT_bondData_temp;
            for(int i = 0; i< 13; i++){
                nextInputWires = {k, CT_r->add(i)}; // k_msg,  CT_r
                hashGadget = allocate<HashGadget>(this, nextInputWires);
                CT_bondData_temp = bond_data->get(i)->add(hashGadget->getOutputWires()[0]);
                addEqualityAssertion(CT_bondData_temp,CT_bondData->get(i), "invalid CT");

            }

            //CT_bond_balance = SKE.Enc(k_msg, bond_balance)
            nextInputWires = {k, CT_r_};
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(bond_balance->add(hashGadget->getOutputWires()[0]),CT_bond_balance, "invalid CT");


            //CT_table = H(table_balance)
            //CT_table = H(table_balance) -> array...
            for(int i = 0 ; i < tableBalanceLength ; i++){
                nextInputWires.push_back(table_balance->get(i));
            }
            
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(hashGadget->getOutputWires()[0], CT_table, "CT_table != H(table_balance)");




            //////////////////////////////////////////// 숫자
            /*bond_data[13]= 
            0 : 채무자ENA, 
            1 : 채권자ENA, 
            2 : 상품명(상품번호), 
            3 : 대출신청금액, 
            4 : 대출기간, 
            5 : 거치기간, 
            6 : 대출개시일, 
            7 : 대출기간만료일, 
            8 : 상환방법, 
            9 : 주택담보대출비율, 
            10: 대출금리, 
            11: 총이자, 
            12: 담보가치*/
            
            WirePtr loanPeriod= bond_data->get(4);
            WirePtr repaymentMethod = bond_data->get(8);


            WirePtr EI = zeroWire; //원리금균등상환  
            WirePtr EP = oneWire; //원금균등상환
            WirePtr PM = oneWire ->add(oneWire); //원금만기일시상환


            BigInteger num = BigInteger("12");
            // loanPeriod = 12
            addEqualityAssertion(loanPeriod, num, "invalid period");

            //대출개시일 < 대출기간만료일
            addOneAssertion(bond_data->get(6)->isLessThanOrEqual(bond_data->get(7), config.LOG2_FIELD_PRIME - 1),"InitationDate less than MaturityDate");


            //대출기간만료일 = 대출개시일 + 대출기간
            WirePtr result = bond_data->get(6)->add(bond_data->get(4));
            addEqualityAssertion(bond_data->get(7), result,"invalid result");
            
            //대출금리 = 3% 고정
            num = BigInteger("3");
            addEqualityAssertion(bond_data->get(10), num,"loanInterestRate != 3"); //3%
            
            //LTV.최소(1%) <= 대출신청금액 / 담보가치*100 <= LTV.최대(70%)

            //LTV.최소(1%) * 담보가치 <= 대출신청금액 * 100 
            //LTV.최대(70%) * 담보가치 >= 대출신청금액 * 100

            //대출신청금액 : bond_data->get(3), 담보가치 : bond_data->get(12)
            BigInteger min = BigInteger("1");
            BigInteger max = BigInteger("70");

            BigInteger num100 = BigInteger("100");

            WirePtr leftResult = bond_data->get(12)->mul(min);
            WirePtr rightResult = bond_data->get(3)->mul(num100);
            
            addOneAssertion(leftResult->isLessThanOrEqual(rightResult, config.LOG2_FIELD_PRIME - 1),"left greater than right");

            leftResult = bond_data->get(12)->mul(max);
            addOneAssertion(leftResult->isGreaterThanOrEqual(leftResult,config.LOG2_FIELD_PRIME - 1), "left less than right");

            
            
















            //vector<WirePtr> plain = {PK_enc_debtor, k_PKE}; //pk_enc_debtor, k_PKE
            // for (int i = 0; i < 2; i++)
            // {
            //     hashGadget = allocate<HashGadget>(this, k->add(i));
            //     addEqualityAssertion((*CT_debtorKey)[i], plain[i]->add(hashGadget->getOutputWires()[0]), "ciphertext is not equal");
            // }
            
            
            // vector<WirePtr> nextInputWires;
            // HashGadget *hashGadget;

            // WirePtr calculated_bank_value = value_new_user->add(value_new_bank);
            // addEqualityAssertion(calculated_bank_value, value_bank , 'invalid value');

            // nextInputWires = {PK_bank->get(1), r, value_bank};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], commitBankValue, "commitBankValue' not equal");
            
            // decryption        
            /* */
            // BondDecryptionGadget *decGadget = allocate<DecryptionGadget>(this, *cin, sk);
            // WirePtr v_in = decGadget->getOutputWires()[0];
            
            // balance check

            // // pin + v_ - v
            // WirePtr v_eval = v_in->add(dv)->sub(dv_)->add(pv)->sub(pv_);
            // addEqualityAssertion(v_out, v_eval, "invalid v_out");

            // commit check

            // hashGadget = allocate<HashGadget>(this, sk);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], k_b, "k_b not equal");
        
            // encryption check

            // ECGroupGeneratorGadget *ecGadget = allocate<ECGroupGeneratorGadget>(this, G, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0], G_r, "G_r not equal");

            // ecGadget = allocate<ECGroupGeneratorGadget>(this, k_u_, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), K_u, "K_u' not equal");

            // ecGadget = allocate<ECGroupGeneratorGadget>(this, apk, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), K_a, "K_a' not equal");

            // vector<WirePtr> plain = {du_, dv_, addr_r};
            // for (int i = 0; i < 3; i++)
            // {
            //     hashGadget = allocate<HashGadget>(this, k->add(i));
            //     addEqualityAssertion((*CT)[i], plain[i]->add(hashGadget->getOutputWires()[0]), "ciphertext is not equal");
            // }




            // addEqualityAssertion(k, SK_user);

            // vector<WirePtr> nextInputWires;
            // HashGadget *hashGadget;

            // /* receive a commitment */
            // hashGadget = allocate<HashGadget>(this, sk);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], k_b, "k_b not equal");

            // nextInputWires = {k_b, k_u};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], addr, "addr not equal");

            // nextInputWires = {du, dv, addr};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], cm, "cm not equal");

            // nextInputWires = {cm, sk};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], sn, "sn not equal");

            // // membership check
            // Wires leafWires = {cm};
            // MerkleTreePathGadget *merkleTreeGadget = allocate<MerkleTreePathGadget>(this, directionSelector, leafWires, *intermediateHashWires, treeHeight, true);
            // addOneAssertion(dv->isEqualTo(zeroWire)->add(rt->isEqualTo(merkleTreeGadget->getOutputWires()[0]))->checkNonZero(),
            //                 "membership failed");

            // /* send a commitment */
            // ECGroupGeneratorGadget *ecGadget = allocate<ECGroupGeneratorGadget>(this, G, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0], G_r, "G_r not equal");

            // ecGadget = allocate<ECGroupGeneratorGadget>(this, k_u_, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), K_u, "K_u' not equal");

            // ecGadget = allocate<ECGroupGeneratorGadget>(this, apk, r);
            // addEqualityAssertion(ecGadget->getOutputWires()[0]->mul(k), K_a, "K_a' not equal");

            // vector<WirePtr> plain = {du_, dv_, addr_r};
            // for (int i = 0; i < 3; i++)
            // {
            //     hashGadget = allocate<HashGadget>(this, k->add(i));
            //     addEqualityAssertion((*CT)[i], plain[i]->add(hashGadget->getOutputWires()[0]), "ciphertext is not equal");
            // }

            // nextInputWires = {k_b_, k_u_};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(addr_r, hashGadget->getOutputWires()[0], "addr' is not equal");

            // nextInputWires = {du_, dv_, addr_r};
            // hashGadget = allocate<HashGadget>(this, nextInputWires);
            // addEqualityAssertion(hashGadget->getOutputWires()[0], cm_, "cm' not equal");

            // /* balance check */
            // DecryptionGadget *decGadget = allocate<DecryptionGadget>(this, *cin, sk);
            // WirePtr v_in = decGadget->getOutputWires()[0];
            // v_in = v_in->mul(((*cin)[0]->add((*cin)[1]))->checkNonZero()); // if ct == 0 then v_in = 0

            // decGadget = allocate<DecryptionGadget>(this, *cout, sk);
            // WirePtr v_out = decGadget->getOutputWires()[0];

            // // WirePtr zeroWire = getZeroWire();

            // // pin + v_ - v
            // WirePtr v_eval = v_in->add(dv)->sub(dv_)->add(pv)->sub(pv_);
            // addEqualityAssertion(v_out, v_eval, "invalid v_out");

            // addOneAssertion(dv->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "dv less than 0");
            // addOneAssertion(dv_->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "dv_ less than 0");
            // addOneAssertion(pv->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "pv less than 0");
            // addOneAssertion(pv_->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "pv_ less than 0");
            // // assert v >= 0
            // addOneAssertion(v_in->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "v less than 0");
            // // assert (vout >= 0)
            // addOneAssertion(v_out->isGreaterThanOrEqual(zeroWire, config.LOG2_FIELD_PRIME - 1), "v_ less than 0");

            return;
        }

        void RequestLending::finalize()
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

        void RequestLending::assignInputs(CircuitEvaluator &circuitEvaluator)
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

        auto generator = new CircuitBuilder::RealEstate::RequestLending("RealEstate", G1_GENERATOR, config);
        generator->generateCircuit();

        return generator;
    }

}