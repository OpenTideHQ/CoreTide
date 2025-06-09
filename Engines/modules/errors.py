
class TideErrors(Exception):
    """
    Container for all custom OpenTIDE errors
    """
    class TideDataModelErrors(Exception):
        """
        Represent all errors related to malformed Tide Objects
        """
        ...
    class TideDeploymentErrors(Exception):
        """
        Represents all errors occuring during a deployment procedure 
        """
        ...

    class TenantConnectionError(Exception):
        """
        Raised when failed to establish a connection to the target tenant
        """
        ...

    class DetectionRulesOperationErrors(TideDeploymentErrors):
        """
        Represents all errors related to Detection Rules API operations 
        """

    class DetectionRuleCreationFailed(Exception): 
        """
        Raised when failed to create a detection rule in the target tenant
        """
        ...

    class DetectionRuleUpdateFailed(DetectionRulesOperationErrors):
        """
        Raised when failed to update a detection rule in the target tenant
        """
        ...

    class DetectionRuleDisablingFailed(DetectionRulesOperationErrors):
        """
        Raised when failed to update a detection rule in the target tenant
        """
        ...

    class DetectionRuleDeletionFailed(DetectionRulesOperationErrors):
        """
        Raised when failed to delete a detection rule in the target tenant
        """
        ...

    class TideConfigurationErrors(Exception):
        """
        Represents all errors related to OpenTIDE Configuration Files
        """
        ...
    class TideSystemConfigurationErrors(TideConfigurationErrors):
        """
        Represents all errors related to OpenTIDE Configuration Files
        """
        ...

    class TideTenantConfigurationErrors(TideSystemConfigurationErrors):
        """
        Represents all errors related to OpenTIDE System Configuration Files
        """
        ...
    class TideTenantConfigurationMissingPermissions(TideSystemConfigurationErrors):
        """
        Represents all errors related to API permissions on target systems
        """
        ...
    class TenantNonExistingDeploymentPlan(TideTenantConfigurationErrors):
        """
        Raised when a tenant uses a non existing deployment plan
        """
        ...
    class TideMDRDataModelErrors(TideDataModelErrors):
        """
        Raised for all errors related to incorrect MDR Data Structures
        """
        ...
    class TideQueryValidationError:
        """
        Raised when the MDR query failed validation
        """
        ...