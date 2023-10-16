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

#include "LiquidateCollateral.hpp"
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

        LiquidateCollateral::LiquidateCollateral(string circuitName, int __treeHeight, const BigInteger &__G1_GENERATOR, Config &config)
            : CircuitBuilder::CircuitGenerator(circuitName, config),
              treeHeight(__treeHeight),
              G1_GENERATOR(__G1_GENERATOR)
        {
        }

        void LiquidateCollateral::buildCircuit()
        {
            /* statements */
            CT_bond_balance = createInputWire("CT_bond_balance");
            CT_table = createInputWire("CT_table");
            cnt = createInputWire("cnt");


            // /* witnesses */
            table_balance = createProverWitnessWireArray(tableBalanceLength, "table_balance");
            bond_balance = createProverWitnessWire("bond_balance");
            k_msg = createProverWitnessWire("k_msg");


            vector<WirePtr> nextInputWires;
            HashGadget *hashGadget;

            //CT_table = H(table_balance)
            //CT_table = H(table_balance) -> array...
            for(int i = 0 ; i < tableBalanceLength ; i++){
                nextInputWires.push_back(table_balance->get(i));
            }
            
            hashGadget = allocate<HashGadget>(this, nextInputWires);
            addEqualityAssertion(hashGadget->getOutputWires()[0], CT_table, "CT_table != H(table_balance)");

            
            // bond_balance = SKE.Dec(k_msg, CT_bond_balance)
            DecryptionGadget *decGadget = allocate<DecryptionGadget>(this, *CT_bond_balance, k_msg);
            addEqualityAssertion(decGadget->getOutputWires()[0], bond_balance, "bond_balance not equal");

            //table_balance[cnt] < bond_balance
            BigInteger cntBigInteger = ((ConstantWire*) cnt)->getConstant();
            string cntString = cntBigInteger.toString();
           // stol(cntString)

            addOneAssertion(table_balance->get(stol(cntString))->isLessThan(bond_balance, config.LOG2_FIELD_PRIME - 1),"table_balance[cnt] >= bond_balance");
            

            return;
        }

        void LiquidateCollateral::finalize()
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

        void LiquidateCollateral::assignInputs(CircuitEvaluator &circuitEvaluator)
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

        auto generator = new CircuitBuilder::RealEstate::LiquidateCollateral("RealEstate", treeHeight, G1_GENERATOR, config);
        generator->generateCircuit();

        return generator;
    }

}