-- Your counter function (works well!)
DEFINE FUNCTION OVERWRITE fn::increment($name: string, $organization:string, $category:string) { 
    RETURN (UPSERT ONLY type::thing('counter', $name) SET `value` += 1, name=$name, organization=$organization,category=$category).`value`; 
} PERMISSIONS FULL;

-- Generate serialised number with manual padding
DEFINE FUNCTION OVERWRITE fn::generate_serial($org: string, $cat: string) {
    LET $today = time::now();
    LET $date = time::format($today, "%y%m%d");
    LET $key = $date + $org + $cat;
    
    LET $counter = fn::increment($key, $org,$cat);
    LET $num_str = <string>$counter;
    
    -- Manual padding to 5 digits
    LET $padded = IF string::len($num_str) == 1 THEN "0000" + $num_str
                  ELSE IF string::len($num_str) == 2 THEN "000" + $num_str  
                  ELSE IF string::len($num_str) == 3 THEN "00" + $num_str
                  ELSE IF string::len($num_str) == 4 THEN "0" + $num_str
                  ELSE $num_str
                  END;
    
    RETURN $key + $padded;
};

    select * from fn::generate_serial("SA","RC");