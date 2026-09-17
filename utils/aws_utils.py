import boto3


def get_aws_session(region=None):
    """
    Create and return a boto3 AWS session.
    """

    return boto3.Session(
        region_name=region
    )


def get_account_id(session=None):
    """
    Get the AWS account ID associated
    with the current credentials.
    """

    session = session or boto3.Session()

    sts_client = session.client("sts")

    response = sts_client.get_caller_identity()

    return response["Account"]


def get_region(session=None):
    """
    Get the AWS region from the session.
    """

    session = session or boto3.Session()

    return session.region_name or "unknown"