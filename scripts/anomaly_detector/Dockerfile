FROM public.ecr.aws/lambda/python:3.11-x86_64

# Copy requirements and install Python dependencies
COPY anomaly_detector/requirements.txt ${LAMBDA_TASK_ROOT}
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Copy shared utilities
COPY shared ${LAMBDA_TASK_ROOT}/shared

# Copy application code
COPY anomaly_detector/anomaly_detector.py ${LAMBDA_TASK_ROOT}

# Copy pre-trained models into the container
COPY models ${LAMBDA_TASK_ROOT}/models

# Set Python path to include shared directory
ENV PYTHONPATH="/var/task/shared:/var/task"

# Set the handler
CMD ["anomaly_detector.lambda_handler"]