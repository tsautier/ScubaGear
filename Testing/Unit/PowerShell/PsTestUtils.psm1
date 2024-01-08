# Powershell module to compare 2 hashtables
# This checks to see if all the keys match
# (no missing keys from either one)
# It will then compare the values to see if these match
#
# Returns $true if above conditions are met otherwise $false
#
#  NOTES:  Value compare is not deep compare

function Compare-Hash{
    param (
        [hashtable] $hash1,
        [hashtable] $hash2
    )
    # Hashes are different if keys do not match
    $keyDifference = (Compare-Object @($hash1.keys) @($hash2.keys))
    # For unit test, inidicate key differences if present
    $hash1_only = $keyDifference |  Where-Object SideIndicator -eq "<=" | Select-Object -ExpandPropert InputObject
    $hash2_only = $keyDifference |  Where-Object SideIndicator -eq "=>" | Select-Object -ExpandPropert InputObject
    if ($hash1_only) { Write-Output("hash2 missing key: " + $hash1_only) }
    if ($hash2_only) { Write-Output("hash1 missing key: " + $hash2_only) }
    # keys are equal, now compare comtents
    $valueDifference = $false
    if ( -Not $keyDifference )
    {
        foreach ($key in $hash1.keys )
        {
            if (Compare-Object $hash1.$key $hash2.$key ){
                $valueDifference = $true
                Write-Output("key {0} values differ {1} and {2}" -f $key, $hash1.$key, $hash2.$key )
            }
        }
    }
    $difference = ( ($keyDifference -ne $none ) -or ($valueDifference) )
    $isSame = ( -Not ( $difference ))
    return $isSame
}

