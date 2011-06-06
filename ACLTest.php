<?php

require_once 'ACL.php';

class ACLTest extends PHPUnit_Framework_TestCase
{
    
    
    
    
    public function testACL()
    {
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
        
        
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res_all'), 'joe.res_all should be allowed' );
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res_all', '*'), 'joe.res_all should be allowed' );
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res_all', null), 'joe.res_all should be allowed' );
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res_all', -1), 'joe.res_all should be allowed' );
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res_all', false), 'joe.res_all should be allowed' );
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res_all', 1), 'joe.res_all should be allowed' );
        
        
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'joe', 'res', 'delete'), 'joe.res.delete should be allowed' );
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'joe', 'res', 'create'), 'joe.res.create should not be allowed' );
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'joe', 'res'), 'joe.res.* should not be allowed' );
        // junk values translate to '*' request permission, which is false
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'joe', 'res', null), 'joe.res.* should not be allowed' );
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'joe', 'res', false), 'joe.res.* should not be allowed' );
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'joe', 'res', -1), 'joe.res.* should not be allowed' );
        
        
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'non_existing_user', 'res'), 'non_existing_user.* should not be allowed to anything' );
        
        
        $this->assertEquals(false, ACL::userIsAllowed($ACL, 'joe', 'res_not_exixsting'), 'joe.res_not_exixsting.* should not be allowed' );
        
        
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'root', 'res_all'), 'root.res_all should be allowed' );
                                                        
        $this->assertEquals(true, ACL::userIsAllowed($ACL, 'toor', 'res_all'), 'toor.res_all should be allowed' );
        
        
        
        $this->assertEquals(true, ACL::roleIsAllowed($ACL, 'admin', 'res'), 'role admin.res should be allowed' );
        $this->assertEquals(true, ACL::roleIsAllowed($ACL, 'admin', 'res', 'add'), 'role admin.res.add should be allowed' ); 
         
        
        $this->assertEquals(true, ACL::roleIsAllowed($ACL, 'admin2', 'res'), 'role admin2.res should be allowed' );
        $this->assertEquals(true, ACL::roleIsAllowed($ACL, 'admin3', 'res'), 'role admin3.res should be allowed' );
        
        $this->assertEquals(false, ACL::roleIsAllowed($ACL, 'writer', 'edit'), 'role writer.edit should not be allowed' );
        
        
        $this->assertEquals(false, ACL::isAllowed( $ACL, 'joe', array(), 'res', 'add'  ), 'joe should not access to res.add' );
        $this->assertEquals(true, ACL::isAllowed( $ACL, 'joe', array('admin'), 'res', 'add'  ), 'joe cant access to res.add, but his group "admin" should' );
  
    }
}
 




