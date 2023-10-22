

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_381/bls12_381_pp.hpp>

#include <SubsetSumHashGadget.hpp>
#include <MerkleTreePathGadget.hpp>
#include <MiMC7Gadget.hpp>
#include <MerkleTreePathGadget.hpp>
#include <ECGroupOperationGadget.hpp>
#include <ECGroupGeneratorGadget.hpp>
#include <HashGadget.hpp>
#include <SHA256Gadget.hpp>
#include <MiMC7Gadget.hpp>
#include <PoseidonGadget.hpp>

#include <api.hpp>
#include "context.hpp"

#include <logging.hpp> 

using namespace libsnark ;
using namespace CircuitBuilder ;
using namespace CircuitBuilder::Gadgets ;

    
namespace libsnark {

    bool globals_initiated = false ;
    
    std::map<std::string , create_circuit_ftn_t> EmbeddedCircuitList ;  

    int last_context_id = 0 ;
    std::map<int , Context_base * > context_list ;
    
    std::mutex createCircuitContext_mtx ;

    map< int , Config > config_list ;
    
    void init_globals(){
        
        if(globals_initiated) return ;
        
        globals_initiated = true ;

        libff::alt_bn128_pp::init_public_params();
        Config config_EC_ALT_BN128 ;
        config_EC_ALT_BN128.EC_Selection = EC_ALT_BN128 ;
        config_EC_ALT_BN128.FIELD_PRIME = BigInteger ( "21888242871839275222246405745257275088548364400416034343698204186575808495617" , 10) ;
        config_EC_ALT_BN128.CURVE_ORDER = BigInteger ( "21888242871839275222246405745257275088597270486034011716802747351550446453784" , 10) ;
        config_EC_ALT_BN128.SUBGROUP_ORDER = BigInteger("2736030358979909402780800718157159386074658810754251464600343418943805806723", 10);
        config_EC_ALT_BN128.LOG2_FIELD_PRIME = config_EC_ALT_BN128.FIELD_PRIME.size_in_base(2);
        config_list[ config_EC_ALT_BN128.EC_Selection ] = config_EC_ALT_BN128 ;

        libff::bls12_381_pp::init_public_params();
        Config config_EC_BLS12_381 ;
        config_EC_BLS12_381.EC_Selection = EC_BLS12_381 ;
        config_EC_BLS12_381.FIELD_PRIME = BigInteger ( "52435875175126190479447740508185965837690552500527637822603658699938581184513" , 10) ;
        config_EC_BLS12_381.CURVE_ORDER = BigInteger ( "21888242871839275222246405745257275088597270486034011716802747351550446453784" , 10) ;
        config_EC_BLS12_381.SUBGROUP_ORDER = BigInteger("2736030358979909402780800718157159386074658810754251464600343418943805806723", 10);
        config_EC_BLS12_381.LOG2_FIELD_PRIME = config_EC_BLS12_381.FIELD_PRIME.size_in_base(2);
        config_list[ config_EC_BLS12_381.EC_Selection ] = config_EC_BLS12_381 ;

        //
        //  Init Gadget static members 
        //
        for ( auto configItr : config_list ){
            SubsetSumHashGadget::init_static_members( configItr.second ) ;
        }
        
        ECGroupOperationGadget::init_static_members() ;
        ECGroupGeneratorGadget::init_static_members() ;
        MiMC7Gadget::init_static_members();
        SHA256Gadget::init_static_members();
        MiMC7Gadget::init_static_members();
        PoseidonGadget::init_static_members();
        

        //
        // Circuit Registration
        //
        #ifdef CIRCUIT_BUILDER_CRV
        extern CircuitGenerator* create_crv_registor_generator( const CircuitArguments & , const Config & ) ;
        extern CircuitGenerator* create_crv_tally_generator( const CircuitArguments & , const Config & ) ;
        extern CircuitGenerator* create_crv_vote_generator( const CircuitArguments & , const Config & ) ;
        EmbeddedCircuitList["Register"] = create_crv_registor_generator  ;
        EmbeddedCircuitList["Tally"] = create_crv_tally_generator ;
        EmbeddedCircuitList["Vote"] = create_crv_vote_generator ;
        #endif

        #ifdef CIRCUIT_BUILDER_ZKLAY
        extern CircuitGenerator* create_crv_zklay_generator( const CircuitArguments & , const Config & ) ;
        EmbeddedCircuitList["ZKlay"] = create_crv_zklay_generator ;
        #endif

        #ifdef CIRCUIT_BUILDER_ZKZKROLLUP
        extern CircuitGenerator* create_crv_zkzkrollup_generator( const CircuitArguments & , const Config & ) ;
        EmbeddedCircuitList["zkzkRollup"] = create_crv_zkzkrollup_generator ;
        #endif

        #ifdef CIRCUIT_BUILDER_NFID
        extern CircuitGenerator* create_crv_nfid_generator( const CircuitArguments & , const Config & ) ;
        EmbeddedCircuitList["NFID"] = create_crv_nfid_generator ;
        #endif
        
        #ifdef CIRCUIT_BUILDER_REAL_ESTATE
        extern CircuitGenerator* create_crv_real_estate_generator( const CircuitArguments & , const Config & ) ;
        EmbeddedCircuitList["RealEstate"] = create_crv_real_estate_generator ;
        #endif
        
        
        LOGD ("\n") ;
        LOGD (" Embedded Circuits :\n") ;
        for ( auto em_c : EmbeddedCircuitList ){
            LOGD ( "    %s\n" , em_c.first.c_str() ) ;
        }
        
        return;
    }
    

    int createCircuitContext(const char * __circuit_name , 
                             int proof_system ,
                             int ec_selection ,
                             const char * __arith_text_path , 
                             const char * __inputs_text_path , 
                             const char * __cs_file_path )
    { 
        
        create_circuit_ftn_t create_circuit_ftn = NULL ;
        Context_base * context = NULL ; 
        int error_code = 0 ;
        
        if ( ! __circuit_name ){ return -1 ; }

        string circuit_name = __circuit_name ;

        string arith_text_path  = ( __arith_text_path )  ? string(__arith_text_path)  : "" ;
        string inputs_text_path = ( __inputs_text_path ) ? string(__inputs_text_path) : "" ;
        string cs_file_path     = ( __cs_file_path )     ? string(__cs_file_path)     : "" ;

        createCircuitContext_mtx.lock() ;

        libsnark::init_globals();

        bool is_embedded_circuit = EmbeddedCircuitList.find( circuit_name ) != EmbeddedCircuitList.end() ;

        if ( is_embedded_circuit && ( !arith_text_path.size() || !inputs_text_path.size() ) ){    
            // using embedded circuit
            create_circuit_ftn = EmbeddedCircuitList[ circuit_name ];
        }else if ( arith_text_path.size() && inputs_text_path.size() ){
            // using Arith/Input files
        }else{
            error_code = -1 ;
        }

        if ( (error_code == 0) && !(proof_system == R1CS_GG || proof_system == R1CS_ROM_SE) ){ 
            error_code = -2 ;
        }

        if ( (error_code == 0) && (config_list.find(ec_selection) == config_list.end()) ){ 
            error_code = -3 ;
        }

        if ( error_code != 0 ){
            createCircuitContext_mtx.unlock() ;
            return error_code ;
        }

        

        int new_id = last_context_id + 1 ;
        while ( context_list.find(new_id) != context_list.end() ){ new_id ++ ; }        
        last_context_id = new_id ;
        
        if ( ec_selection == EC_ALT_BN128 ){
            
            context = new Context< libff::Fr<libff::alt_bn128_pp > ,  libff::alt_bn128_pp , libff::alt_bn128_pp >(
                                last_context_id , 
                                circuit_name , 
                                proof_system , 
                                config_list[ec_selection],
                                create_circuit_ftn ,
                                arith_text_path , 
                                inputs_text_path ,
                                cs_file_path );
        
        }else if ( ec_selection == EC_BLS12_381 ){
        
            context = new Context< libff::Fr<libff::bls12_381_pp > ,  libff::bls12_381_pp , libff::bls12_381_pp >(
                            last_context_id , 
                            circuit_name , 
                            proof_system , 
                            config_list[ec_selection],
                            create_circuit_ftn ,
                            arith_text_path , 
                            inputs_text_path ,
                            cs_file_path );
        
        }
        
        context_list[last_context_id] = context ;

        createCircuitContext_mtx.unlock() ;
        
        return last_context_id ;
    }
}



#ifdef __cplusplus
extern "C" {
#endif

    int createCircuitContext(const char * circuit_name , 
                             int proof_system ,
                             int ec_selection ,
                             const char * arith_text_path , 
                             const char * inputs_text_path , 
                             const char * cs_file_path )
    { 
        return 
        libsnark::createCircuitContext( circuit_name , 
                                        proof_system ,
                                        ec_selection ,
                                        arith_text_path , 
                                        inputs_text_path , 
                                        cs_file_path );
    }

    int buildCircuit (int context_id ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->build_circuit() ;
    }

    int assignCircuitArgument(
            int context_id , 
            const char * arg_key , 
            const char * arg_value  )
    {
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->assign_circuit_argument(arg_key , arg_value ) ;
    }

    int runSetup (int context_id ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->run_setup() ;
    }

    int runProof (int context_id ) {
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->run_proof() ;
    }

    int runVerify (int context_id  ) {
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->run_verify() ;
    }

    int writeConstraintSystem(int context_id , const char* file_name , int use_compression , const char* checksum_prefix ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->write_cs(file_name , ( use_compression == 1 ) , string(checksum_prefix) ) ;
    }

    int verifyConstraintSystemFileChecksum( int context_id , const char* file_name , const char* checksum_prefix ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->verify_cs_chechsum(file_name , string(checksum_prefix) ) ;
    }

    int writeCircuitToFile(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->write_circuit_to_file(file_name) ;
    }

    int writeInputsToFile(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->write_inputs_to_file(file_name) ;
    }


    int updatePrimaryInput(int context_id , const char* input_name , int value ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->update_primary_input(input_name, value) ;
    }

    int updatePrimaryInputStr(int context_id , const char* input_name , const char * value_str ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->update_primary_input_strValue(input_name, value_str) ;
    }

    int updatePrimaryInputArray(int context_id , const char* input_name , int array_index, int value ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->update_primary_input_array(input_name, array_index, value ) ;
    }

    int updatePrimaryInputArrayStr(int context_id , const char* input_name , int array_index, const char * value_str ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->update_primary_input_array_strValue(input_name , array_index , value_str ) ;
    }

    int resetPrimaryInputArray(int context_id , const char* input_name , int value ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->reset_primary_input_array(input_name, value ) ;
    }

    int resetPrimaryInputArrayStr(int context_id , const char* input_name , const char * value_str ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->reset_primary_input_array_strValue(input_name , value_str ) ;
    }

    int updatePrimaryInputFromJson(int context_id , const char* input_json_string ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->update_primary_input_from_json( input_json_string ) ;
    }


    int writeVK(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->write_vk(file_name) ;
    }

    int readVK(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->read_vk(file_name) ;
    }

    int writePK(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->write_pk(file_name) ;
    }

    int readPK(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->read_pk(file_name) ;
    }

    int writeProof(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->write_proof(file_name) ;
    }

    int readProof(int context_id , const char* file_name){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->read_proof(file_name) ;
    }

    const char* serializeProofKey(int context_id ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return NULL ; }
        return ItC->second->serialize_pk_object() ;
    }

    int deSerializeProofKey(int context_id , const char* json_string){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->de_serialize_pk_object(json_string) ;
    }

    const char* serializeVerifyKey(int context_id ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return NULL ; }
        return ItC->second->serialize_vk_object() ;
    }

    int deSerializeVerifyKey(int context_id , const char* json_string){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->de_serialize_vk_object(json_string) ;
    }

    const char* serializeProof(int context_id ){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return NULL ; }
        return ItC->second->serialize_proof_object() ;
    }

    int deSerializeProof(int context_id , const char* json_string){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->de_serialize_proof_object(json_string) ;
    }

    int serializeFormat(int context_id ,  int format ) {
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        return ItC->second->get_set_serialize_format(format) ;
    }

    int finalizeCircuit( int context_id ){
        
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return -1 ; }
        Context_base *C = ItC->second ;

        LOGD("finalize_circuit arguments :\n" );
        LOGD("context_id                 : %d\n", context_id );

        context_list.erase(context_id) ;
        delete C ;
        C = NULL ;
        
        return 0;
    }

    int finalizeAllCircuit(){
        auto context_list_copy = context_list ;
        for( auto ItC : context_list_copy ){
            int context_id = ItC.first ;
            Context_base *C = ItC.second ;
            delete C ;
            C = NULL ;
            context_list.erase(context_id) ;
        }
        return context_list_copy.size();
    }


    const char * getLastFunctionMsg(int context_id){
        auto ItC = context_list.find(context_id) ;
        if( ItC == context_list.end()){ ContextIdErr ; return NULL ; }
        return ItC->second->get_last_function_msg();
    }


#ifdef __cplusplus
}
#endif