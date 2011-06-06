<?php

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


ok( ACL::userIsAllowed($ACL, 'joe', 'res_all'), 'joe.res_all should be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res_all', '*'), 'joe.res_all should be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res_all', null), 'joe.res_all should be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res_all', -1), 'joe.res_all should be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res_all', false), 'joe.res_all should be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res_all', 1), 'joe.res_all should be allowed' );


ok( ACL::userIsAllowed($ACL, 'joe', 'res', 'delete'), 'joe.res.delete should be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res', 'create')===false, 'joe.res.create should not be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res') === false, 'joe.res.* should not be allowed' );
// junk values translate to '*' request permission, which is false
ok( ACL::userIsAllowed($ACL, 'joe', 'res', null) === false, 'joe.res.* should not be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res', false) === false, 'joe.res.* should not be allowed' );
ok( ACL::userIsAllowed($ACL, 'joe', 'res', -1) === false, 'joe.res.* should not be allowed' );


ok( ACL::userIsAllowed($ACL, 'non_existing_user', 'res') === false, 'non_existing_user.* should not be allowed to anything' );


ok( ACL::userIsAllowed($ACL, 'joe', 'res_not_exixsting') === false, 'joe.res_not_exixsting.* should not be allowed' );


ok( ACL::userIsAllowed($ACL, 'root', 'res_all'), 'root.res_all should be allowed' );
                                                
ok( ACL::userIsAllowed($ACL, 'toor', 'res_all'), 'toor.res_all should be allowed' );



ok( ACL::roleIsAllowed($ACL, 'admin', 'res'), 'role admin.res should be allowed' );
ok( ACL::roleIsAllowed($ACL, 'admin', 'res', 'add'), 'role admin.res.add should be allowed' ); 
 

ok( ACL::roleIsAllowed($ACL, 'admin2', 'res'), 'role admin2.res should be allowed' );
ok( ACL::roleIsAllowed($ACL, 'admin3', 'res'), 'role admin3.res should be allowed' );

ok( ACL::roleIsAllowed($ACL, 'writer', 'edit') === false, 'role writer.edit should not be allowed' );


ok( ACL::isAllowed( $ACL, 'joe', array(), 'res', 'add'  ) === false, 'joe should not access to res.add' );
ok( ACL::isAllowed( $ACL, 'joe', array('admin'), 'res', 'add'  ), 'joe cant access to res.add, but his group "admin" should' );
  
