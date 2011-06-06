<?php
/*
porpuse:
    determine if a user can access a resource and eventually do an action on the resource
*/
class ACL {
    
    function is_allowed( ArrayAccess $ACL, $user_id, array $roles, $resource_id, $action = '*'  ){
        $allowed = ACL::user_is_allowed($ACL, $user_id, $resource_id, $action );
        
        if( !$allowed ){
            foreach( $roles as $role ){
                $allowed = ACL::role_is_allowed($ACL, $role, $resource_id, $action );
                if( $allowed ){
                    break;
                }
            }
        }
        return $allowed;
    }
    
    /*
    determina se, l'utente selezionato ha permessi per la risorsa+azione secondo 
    i dati contenuti nella lista $ACL
    $resource_id può essere qualunque cosa, controllers, tabelle, files
    */
    public static function user_is_allowed(ArrayAccess $ACL, $user_id, $resource_id, $action = '*' ){
        $allowed = false;

        
        if(  $user_id === '__groups__' ){
            die("non puoi chiamre ACL::user_is_allowed di un utente con id '__groups__'! "); 
        }
        
        if( !is_string($resource_id) || empty($resource_id) ){
            die("non puoi chiamre ACL::user_is_allowed per una risorsa vuota:".var_dump($resource_id) ); 
        }
        
        if( !is_string($user_id) || empty($user_id) ){
            die("non puoi chiamre ACL::user_is_allowed per uno user vuoto:".var_dump($resource_id) ); 
        }        
        
        // se non è chiaro a cosa si sta accedendo, si sta richiedendo accesso con pieni poteri
        if( !is_string($action) ){
            $action = '*';
        } 

        
        if( isset($ACL[$user_id]) ){
            
            if( $ACL[$user_id] === '*' || in_array('*', $ACL[$user_id]) ){
                // è superadmin, accede a qualsiasi risorsa
                $allowed = true;
            } elseif( isset($ACL[$user_id][$resource_id]) ){
                
                // nessuna particolare azione, l'utente è abilitato di default
                // l'utente ha tutti i permessi su tutta la risorsa, l'utente è abilitato
                if( isset($ACL[$user_id][$resource_id]['*']) ){
                    $allowed = true;
                } else {
                    if( in_array( $action, $ACL[$user_id][$resource_id] )  ){
                        $allowed = true;
                    } else {
                        //  debug
                        $allowed = false;
                    }
                }
            } else {
                // debug
                //echo "'$action' not allowed for \$ACL[$user_id][$resource_id], which is: ".implode(',', $ACL[$user_id][$resource_id]);
            }
        } else {
            // debug
            //echo "user not found !isset(\$ACL[$user_id])";
        }
        
        return $allowed;
    } 
    
    /*
    Role based access list
    */
    function role_is_allowed(ArrayAccess $ACL, $role, $resource_id, $action = '*' ){
        $allowed = false;
        
        // se non è chiaro a cosa si sta accedendo, si sta richiedendo accesso con pieni poteri
        if( !is_string($action) ){
            $action = '*';
        }   
        if( !isset($ACL['__groups__']) ){
            return false;
        }
        
        $GACL = $ACL['__groups__'];
        
        if( isset($GACL[$role]) ){
            
            // è superadmin, accede a qualsiasi risorsa
            if( $GACL[$role] === '*' || in_array('*', $GACL[$role]) ){
                
                $allowed = true;
            } elseif( isset($GACL[$role][$resource_id]) ){
                
                // se è admin, ha tutti i privilegi sulla risorsa 
                // o ha il privilegio specifico sulla srisorsa
                if( $GACL[$role][$resource_id] == '*' 
                    || in_array( '*', $GACL[$role][$resource_id] ) 
                    || in_array( $action, $GACL[$role][$resource_id] )  
                   ){
                
                    $allowed = true;
                } else {
                    //  debug
                    $allowed = false;
                }                
            }
        } else {
        }
        
        return $allowed;
    }     
    
}






/*
    il più semplice tipo di contenitore di dato, un decoratore di array
*/
class ACL_starage_array implements ArrayAccess {
    private $data = array();
    public function __construct($data) {
        $this->data = $data;
    }
    public function offsetExists($offset) {
        return isset($this->data[$offset]);
    }

    public function offsetGet($offset) {
        return isset($this->data[$offset]) ? $this->data[$offset] : null;
    }
    
    // metodi per la scrittura, non necessari in questo caso
    public function offsetSet($offset, $value) {
    //    if (is_null($offset)) {
    //        $this->data[] = $value;
    //    } else {
    //        $this->data[$offset] = $value;
    //    }
    }
    public function offsetUnset($offset) {
    //    unset($this->data[$offset]);
    }    
}


//------------------------------------------------------------------------------
//  minimalist testing
//------------------------------------------------------------------------------

function ok($test, $msg){
    if( $test !== true ){
        echo "! $msg <br>\n";
    }
}

// the framework should configure and load data

$ACL = new ACL_starage_array(
    array(
    'joe' => array(
            'res' => array('delete'),
            'res_all' => array('*')
        ),
    'root' => array( '*' ),
    'toor' => '*',
    
    '__groups__' => array(
            'admin' => array(
                'res' => array('*')
            ),
            'admin2' => array(
                '*'
            ),  
            'admin3' =>  '*',
            
            'writer' => array(
                'res' =>array('add')
            ),
            'editor' => array(
                'res' =>array('add', 'edit')
            ),
            'supervisor' => array(
                'res' =>array('add', 'edit', 'delete')
            )
        )
) );


//------------------------------------------------------------------------------
//  tests
//------------------------------------------------------------------------------


ok( ACL::user_is_allowed($ACL, 'joe', 'res_all'), 'joe.res_all should be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res_all', '*'), 'joe.res_all should be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res_all', null), 'joe.res_all should be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res_all', -1), 'joe.res_all should be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res_all', false), 'joe.res_all should be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res_all', 1), 'joe.res_all should be allowed' );


ok( ACL::user_is_allowed($ACL, 'joe', 'res', 'delete'), 'joe.res.delete should be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res', 'create')===false, 'joe.res.create should not be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res') === false, 'joe.res.* should not be allowed' );
// junk values translate to '*' request permission, which is false
ok( ACL::user_is_allowed($ACL, 'joe', 'res', null) === false, 'joe.res.* should not be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res', false) === false, 'joe.res.* should not be allowed' );
ok( ACL::user_is_allowed($ACL, 'joe', 'res', -1) === false, 'joe.res.* should not be allowed' );


ok( ACL::user_is_allowed($ACL, 'non_existing_user', 'res') === false, 'non_existing_user.* should not be allowed to anything' );


ok( ACL::user_is_allowed($ACL, 'joe', 'res_not_exixsting') === false, 'joe.res_not_exixsting.* should not be allowed' );


ok( ACL::user_is_allowed($ACL, 'root', 'res_all'), 'root.res_all should be allowed' );
                                                
ok( ACL::user_is_allowed($ACL, 'toor', 'res_all'), 'toor.res_all should be allowed' );



ok( ACL::role_is_allowed($ACL, 'admin', 'res'), 'role admin.res should be allowed' );
ok( ACL::role_is_allowed($ACL, 'admin', 'res', 'add'), 'role admin.res.add should be allowed' ); 
 

ok( ACL::role_is_allowed($ACL, 'admin2', 'res'), 'role admin2.res should be allowed' );
ok( ACL::role_is_allowed($ACL, 'admin3', 'res'), 'role admin3.res should be allowed' );

ok( ACL::role_is_allowed($ACL, 'writer', 'edit') === false, 'role writer.edit should not be allowed' );


ok( ACL::is_allowed( $ACL, 'joe', array(), 'res', 'add'  ) === false, 'joe should not access to res.add' );
ok( ACL::is_allowed( $ACL, 'joe', array('admin'), 'res', 'add'  ), 'joe cant access to res.add, but his group "admin" should' );
  
