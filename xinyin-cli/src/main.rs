use inquire::{
    CustomType, Password,
    ui::RenderConfig,
    validator::{ErrorMessage, Validation},
};
use xinyin::generate_words32;

fn main() {
    let xinyin_words = Password::new("输入铭记于心的一句话:")
        .with_custom_confirmation_message("重复输入，用于确认:")
        .with_custom_confirmation_error_message("两次输入不一致，请重新输入")
        .prompt()
        .expect("Failed to read password");

    let (start, count) = prompt_sub_chartset_range()
        .prompt()
        .expect("Failed to read range");

    let secret_key = prompt_secret_key()
        .prompt()
        .expect("Failed to read secret key");

    let words = generate_words32(&xinyin_words, start, count, secret_key.as_deref())
        .expect("Failed to generate words");
    println!("生成的32个字: {:?}", words);
}

fn prompt_secret_key() -> CustomType<'static, Option<Vec<u8>>> {
    return CustomType {
        message: "输入指定SecretKey:",
        starting_input: None,
        default: None,
        placeholder: None,
        help_message: None,
        formatter: &|key: Option<Vec<u8>>| format!("SecretKey: {:?}", key),
        default_value_formatter: &|key: Option<Vec<u8>>| format!("SecretKey: {:?}", key),
        parser: &|input: &str| {
            if input.trim().is_empty() {
                return Ok(None);
            }
            input
                .split(',')
                .map(|s| {
                    let s = s.trim();
                    if let Some(hex) = s.strip_prefix("0x") {
                        u8::from_str_radix(hex, 16)
                    } else {
                        s.parse::<u8>()
                    }
                })
                .collect::<Result<Vec<u8>, _>>()
                .map(Some)
                .map_err(|_| ())
        },
        validators: vec![Box::new(|key: &Option<Vec<u8>>| match key {
            Some(vec) => {
                if vec.len() != 32 {
                    Ok(Validation::Invalid(ErrorMessage::Custom(
                        "SecretKey必须是32个字节".to_string(),
                    )))
                } else {
                    Ok(Validation::Valid)
                }
            }
            None => Ok(Validation::Valid),
        })],
        error_message: "SecretKey格式不正确，使用英语输入法输入 0,1,2,...,31".to_string(),
        render_config: RenderConfig::default(),
    };
}

fn prompt_sub_chartset_range() -> CustomType<'static, (usize, usize)> {
    return CustomType {
        message: "输入选取的规范字范围:",
        starting_input: Some("6,666"),
        default: Some((6, 666)),
        placeholder: None,
        help_message: None,
        formatter: &|(start, count)| format!("{},{}", start, count),
        default_value_formatter: &|(start, count)| format!("{},{}", start, count),
        parser: &|input: &str| {
            let parts: Vec<&str> = input.split(',').collect();
            if parts.len() != 2 {
                return Err(());
            }
            let start = parts[0].trim().parse::<usize>().map_err(|_| ())?;
            let count = parts[1].trim().parse::<usize>().map_err(|_| ())?;
            Ok((start, count))
        },
        validators: vec![Box::new(|(start, count): &(usize, usize)| {
            let start = *start;
            let count = *count;
            if count <= 500 {
                Ok(Validation::Invalid(ErrorMessage::Custom(
                    "范字范围必须是非负整数且计数大于500".to_string(),
                )))
            } else if start < 1 || start > 7600 {
                Ok(Validation::Invalid(ErrorMessage::Custom(
                    "范字范围的起始位置必须在1到7600之间".to_string(),
                )))
            } else if count + start > 8105 {
                Ok(Validation::Invalid(ErrorMessage::Custom(
                    "范字范围超过了8105".to_string(),
                )))
            } else {
                Ok(Validation::Valid)
            }
        })],
        error_message: "范字范围格式不正确，使用英语输入法输入 start,count".to_string(),
        render_config: RenderConfig::default(),
    };
}
