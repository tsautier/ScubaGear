# Powershell module to compare 2 hashtables
# This checks to see if all the keys match
# (no missing keys from either one)
# It will then compare the values to see if these match
#
# Returns $true if above conditions are met otherwise $false
#
#  NOTES:  Value compare is not deep compare

function Compare-Hashes{
    param (
        [hashtable] $hash1,
        [hashtable] $hash2
    )

    # These members are arrays and this code does not support embedded arrays
    # So for now I need to exclude this from the comparison
    $excludedKeys = @( 'AnObject','ProductNames')
    $compare = $true

    $arr1 = @()
    $arr2 = @()

    foreach ($key in $hash1.keys){
        if (-Not ( $key -in $excludedKeys )){
            $arr1 += $key
        }
    }
    foreach ($key in $hash2.keys){
        if (-Not ( $key -in $excludedKeys )){
            $arr2 += $key
        }
    }

    foreach ($key in $arr1) {
        if ( -Not ( $hash2.ContainsKey($key ))) {
            Write-Host("1st hash key {0} not in 2nd hash" -f $key )
            $compare = $false
        }
    }
    foreach ($key in $arr2) { 
        if ( -Not ( $hash1.ContainsKey($key ))) {
            Write-Host("2nd hash key {0} not in 1st hash" -f $key )
            $compare = $false
        }
    }
    if ($compare) {
        foreach ($key in $arr1 )
        {
            $hash1_key = $hash1[$key]
            $hash2_key = $hash2[$key]
            if ( -Not ( $hash1_key -eq $hash2_key )) {
                Write-Host("key {0} values differ {1} and {2}" -f $key, $hash1_key, $hash2_key )
                $compare = $false
            }
        }
    }
    return $compare
}

